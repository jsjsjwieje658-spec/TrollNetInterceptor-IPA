//
//  test_tap.c
//  AetherNet — P3 kernel-tap lane simulation
//
//  WHAT IS REAL HERE AND WHAT IS NOT
//  ---------------------------------
//  On the device the tap reads raw frames from /dev/bpfN.  A build host inside
//  a container cannot open a packet socket (no CAP_NET_RAW) and cannot create
//  a tap device, so the *source* is replaced: the harness opens real UDP and
//  TCP sockets on loopback, exchanges real payload bytes, and hands the
//  tap pipeline complete Ethernet/IPv4/TCP|UDP frames whose 5-tuples come
//  from getsockname()/getpeername() on those live sockets.
//
//  Everything downstream of the source is the shipped code path:
//     AetherBPFIterate → AetherParseLinkFrame → AetherClassifyDirection →
//     AetherFlowTableRecord → shared-memory counters
//
//  So this test covers the framing arithmetic, the parsers, the per-PID port
//  matching, the RX/TX classification and the accounting — the part where a
//  mistake would silently produce wrong numbers.  Only the two ioctl calls
//  that open the device (BIOCSETIF / BIOCSETF) are not exercised.
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../Core/L4Engine/AetherPacketCore.h"
#include "host_support.h"

static int gFailures = 0;
static int gChecks = 0;

#define CHECK(cond, ...) do {                                        \
    gChecks++;                                                       \
    if (!(cond)) {                                                   \
        gFailures++;                                                 \
        printf("  ✘ %s:%d: ", __func__, __LINE__);                   \
        printf(__VA_ARGS__);                                         \
        printf("\n");                                                \
    }                                                                \
} while (0)

#define CHECK_EQ(actual, expected, label) do {                       \
    long long a_ = (long long)(actual);                              \
    long long e_ = (long long)(expected);                            \
    gChecks++;                                                       \
    if (a_ != e_) {                                                  \
        gFailures++;                                                 \
        printf("  ✘ %s:%d: %s expected %lld, got %lld\n",            \
               __func__, __LINE__, label, e_, a_);                   \
    }                                                                \
} while (0)

// ---------------------------------------------------------------------------
// Frame construction from a real socket pair
// ---------------------------------------------------------------------------
static size_t BuildFrame(uint8_t *buf, size_t bufLen,
                         const struct sockaddr_in *src,
                         const struct sockaddr_in *dst,
                         uint8_t proto, const uint8_t *payload, size_t payloadLen) {
    if (bufLen < 54 + payloadLen) return 0;
    memset(buf, 0, bufLen);

    buf[12] = 0x08; buf[13] = 0x00;                       // EtherType IPv4
    size_t ip = 14;
    uint16_t total = (uint16_t)(20 + (proto == IPPROTO_TCP ? 20 : 8) + payloadLen);
    buf[ip + 0] = 0x45;
    buf[ip + 2] = (uint8_t)(total >> 8);
    buf[ip + 3] = (uint8_t)(total & 0xFF);
    buf[ip + 8] = 64;
    buf[ip + 9] = proto;
    memcpy(buf + ip + 12, &src->sin_addr, 4);
    memcpy(buf + ip + 16, &dst->sin_addr, 4);
    uint16_t sport = ntohs(src->sin_port);
    uint16_t dport = ntohs(dst->sin_port);

    size_t l4 = ip + 20;
    buf[l4 + 0] = (uint8_t)(sport >> 8); buf[l4 + 1] = (uint8_t)(sport & 0xFF);
    buf[l4 + 2] = (uint8_t)(dport >> 8); buf[l4 + 3] = (uint8_t)(dport & 0xFF);
    if (proto == IPPROTO_TCP) {
        buf[l4 + 12] = (uint8_t)((20 / 4) << 4);
        buf[l4 + 13] = 0x10;                              // ACK
        l4 += 20;
    } else {
        uint16_t ulen = (uint16_t)(8 + payloadLen);
        buf[l4 + 4] = (uint8_t)(ulen >> 8);
        buf[l4 + 5] = (uint8_t)(ulen & 0xFF);
        l4 += 8;
    }
    if (payloadLen) memcpy(buf + l4, payload, payloadLen);
    return l4 + payloadLen;
}

typedef struct {
    AetherPortSet  ports;
    AetherFlowTable *flows;
    int            udpTX, udpRX;
    int            tcpTX, tcpRX;
    int            unmatched;
} TapCtx;

static void TapFrameSink(void *ctxRaw, const uint8_t *frame, size_t len) {
    TapCtx *ctx = (TapCtx *)ctxRaw;
    AetherParsedPacket p;
    if (AetherParseLinkFrame(frame, len, AETHER_DLT_EN10MB, &p) != 0) return;
    if (p.proto != AETHER_IPPROTO_TCP && p.proto != AETHER_IPPROTO_UDP) return;

    bool isTX = false;
    if (!AetherClassifyDirection(&p, &ctx->ports, &isTX)) { ctx->unmatched++; return; }

    if (p.proto == AETHER_IPPROTO_UDP) { if (isTX) ctx->udpTX++; else ctx->udpRX++; }
    else                               { if (isTX) ctx->tcpTX++; else ctx->tcpRX++; }

    AetherFlowTableRecord(ctx->flows, &p, isTX, p.ipTotalLen, 0);
}

// Counting sink for the record-walk guard test below.
typedef struct { int frames; } WalkCount;
static void WalkCountSink(void *ctxRaw, const AetherBPFMeta *meta,
                          const uint8_t *frame, size_t caplen) {
    (void)meta; (void)frame;
    WalkCount *wc = (WalkCount *)ctxRaw;
    if (caplen > 0) wc->frames++;
}

// Records are built the way the kernel writes them on the device: native
// (little endian) 32 bit fields and a little endian bh_hdrlen.  The timestamp
// is left zero, so the walker falls back to the 16 byte timeval framing —
// the other layout is covered by TestBPFExtHeader / TestBPFDeviceBytes in
// test_core.
static int BuildBPFBatch(uint8_t *out, size_t outLen,
                         const uint8_t *frame, size_t frameLen, int copies) {
    size_t off = 0;
    for (int i = 0; i < copies; i++) {
        if (off + AETHER_BPF_HDR_SIZE + frameLen > outLen) break;
        memset(out + off, 0, AETHER_BPF_HDR_SIZE);
        for (int b = 0; b < 4; b++) {
            out[off + 16 + b] = (uint8_t)((frameLen >> (8 * b)) & 0xFF);  // bh_caplen
            out[off + 20 + b] = (uint8_t)((frameLen >> (8 * b)) & 0xFF);  // bh_datalen
        }
        out[off + 24] = (uint8_t)AETHER_BPF_HDR_SIZE;   // bh_hdrlen (LE u_short)
        out[off + 25] = 0;
        memcpy(out + off + AETHER_BPF_HDR_SIZE, frame, frameLen);
        off += AETHER_BPF_WORDALIGN(AETHER_BPF_HDR_SIZE + frameLen);
    }
    return (int)off;
}

int main(void) {
    setenv("AETHER_TEST_SHM", "/tmp/aether-tap-test.shm", 1);
    setenv("AETHER_TEST_LOG", "/tmp/aether-tap-test.log", 1);
    remove("/tmp/aether-tap-test.shm");

    printf("── P3 kernel tap pipeline simulation ──────────────────────\n");

    // --- 1. Real sockets: a UDP flow and a TCP flow on loopback -------------
    int udpA = socket(AF_INET, SOCK_DGRAM, 0);
    int udpB = socket(AF_INET, SOCK_DGRAM, 0);
    int tcpListen = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(udpA >= 0 && udpB >= 0 && tcpListen >= 0, "sockets created");
    if (udpA < 0 || udpB < 0 || tcpListen < 0) return 1;

    int one = 1;
    setsockopt(tcpListen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a, b, la;
    socklen_t slen = sizeof(a);
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b)); memset(&la, 0, sizeof(la));
    a.sin_family = b.sin_family = la.sin_family = AF_INET;
    a.sin_addr.s_addr = b.sin_addr.s_addr = la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0; b.sin_port = 0; la.sin_port = 0;

    CHECK(bind(udpA, (struct sockaddr *)&a, sizeof(a)) == 0, "bind udpA");
    CHECK(bind(udpB, (struct sockaddr *)&b, sizeof(b)) == 0, "bind udpB");
    CHECK(bind(tcpListen, (struct sockaddr *)&la, sizeof(la)) == 0, "bind tcp listen");
    CHECK(listen(tcpListen, 4) == 0, "listen");

    getsockname(udpA, (struct sockaddr *)&a, &slen);
    getsockname(udpB, (struct sockaddr *)&b, &slen);
    struct sockaddr_in listenAddr;
    slen = sizeof(listenAddr);
    getsockname(tcpListen, (struct sockaddr *)&listenAddr, &slen);

    CHECK(connect(udpA, (struct sockaddr *)&b, sizeof(b)) == 0, "connect udp");

    int tcpClient = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(tcpClient, (struct sockaddr *)&listenAddr, sizeof(listenAddr)) == 0, "connect tcp");
    int tcpServer = accept(tcpListen, NULL, NULL);
    CHECK(tcpServer >= 0, "accept tcp");

    struct sockaddr_in tcpClientAddr, tcpServerAddr;
    slen = sizeof(tcpClientAddr);
    getsockname(tcpClient, (struct sockaddr *)&tcpClientAddr, &slen);
    slen = sizeof(tcpServerAddr);
    getsockname(tcpServer, (struct sockaddr *)&tcpServerAddr, &slen);

    // --- 2. Real bytes over those sockets -----------------------------------
    const char *udpMsg = "UDP-PAYLOAD-FROM-THE-REAL-SOCKET";
    const char *tcpMsg = "TCP-PAYLOAD-FROM-THE-REAL-SOCKET";
    ssize_t udpSent = send(udpA, udpMsg, strlen(udpMsg), 0);
    ssize_t tcpSent = send(tcpClient, tcpMsg, strlen(tcpMsg), 0);
    CHECK_EQ(udpSent, (ssize_t)strlen(udpMsg), "udp bytes on the wire");
    CHECK_EQ(tcpSent, (ssize_t)strlen(tcpMsg), "tcp bytes on the wire");

    char rbuf[256];
    struct timeval tv = { 1, 0 };
    setsockopt(udpB, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcpServer, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t udpGot = recv(udpB, rbuf, sizeof(rbuf), 0);
    ssize_t tcpGot = recv(tcpServer, rbuf, sizeof(rbuf), 0);
    CHECK_EQ(udpGot, (ssize_t)strlen(udpMsg), "udp bytes really received");
    CHECK_EQ(tcpGot, (ssize_t)strlen(tcpMsg), "tcp bytes really received");

    // --- 3. Feed the tap pipeline with frames built from the live tuples ----
    TapCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    AetherPortSetClear(&ctx.ports);
    AetherPortSetAdd(&ctx.ports, ntohs(a.sin_port));           // target = udpA
    AetherPortSetAdd(&ctx.ports, ntohs(tcpClientAddr.sin_port)); // target = tcpClient
    ctx.flows = AetherFlowTableCreate(256);

    uint8_t frame[512];
    uint8_t batch[4096];

    // Outbound UDP (target → peer) and inbound UDP (peer → target)
    size_t flen = BuildFrame(frame, sizeof(frame), &a, &b, IPPROTO_UDP,
                             (const uint8_t *)udpMsg, strlen(udpMsg));
    int blen = BuildBPFBatch(batch, sizeof(batch), frame, flen, 3);
    AetherBPFIterate(batch, (size_t)blen, &ctx, TapFrameSink);
    CHECK_EQ(ctx.udpTX, 3, "3 outbound UDP packets attributed TX");

    flen = BuildFrame(frame, sizeof(frame), &b, &a, IPPROTO_UDP,
                      (const uint8_t *)udpMsg, strlen(udpMsg));
    blen = BuildBPFBatch(batch, sizeof(batch), frame, flen, 2);
    AetherBPFIterate(batch, (size_t)blen, &ctx, TapFrameSink);
    CHECK_EQ(ctx.udpRX, 2, "2 inbound UDP packets attributed RX");

    // TCP outbound + inbound
    flen = BuildFrame(frame, sizeof(frame), &tcpClientAddr, &tcpServerAddr,
                      IPPROTO_TCP, (const uint8_t *)tcpMsg, strlen(tcpMsg));
    blen = BuildBPFBatch(batch, sizeof(batch), frame, flen, 4);
    AetherBPFIterate(batch, (size_t)blen, &ctx, TapFrameSink);
    CHECK_EQ(ctx.tcpTX, 4, "4 outbound TCP packets attributed TX");

    flen = BuildFrame(frame, sizeof(frame), &tcpServerAddr, &tcpClientAddr,
                      IPPROTO_TCP, (const uint8_t *)tcpMsg, strlen(tcpMsg));
    blen = BuildBPFBatch(batch, sizeof(batch), frame, flen, 5);
    AetherBPFIterate(batch, (size_t)blen, &ctx, TapFrameSink);
    CHECK_EQ(ctx.tcpRX, 5, "5 inbound TCP packets attributed RX");

    // A third-party flow must not be counted
    struct sockaddr_in other;
    memset(&other, 0, sizeof(other));
    other.sin_family = AF_INET;
    other.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    other.sin_port = htons((uint16_t)(ntohs(a.sin_port) + 7));
    flen = BuildFrame(frame, sizeof(frame), &other, &b, IPPROTO_UDP,
                      (const uint8_t *)udpMsg, strlen(udpMsg));
    blen = BuildBPFBatch(batch, sizeof(batch), frame, flen, 6);
    AetherBPFIterate(batch, (size_t)blen, &ctx, TapFrameSink);
    CHECK_EQ(ctx.unmatched, 6, "foreign flow not attributed to the target");
    CHECK_EQ(ctx.udpTX, 3, "foreign flow did not inflate TX");
    CHECK_EQ(ctx.udpRX, 2, "foreign flow did not inflate RX");

    // --- 4. Flow table -------------------------------------------------------
    // A pair is ONE flow: outbound (a→b) and inbound (b→a) both key on the
    // target's local port plus the remote endpoint.
    CHECK_EQ(AetherFlowTableCount(ctx.flows), 2, "one UDP flow + one TCP flow");
    AetherFlowEntry snap[16];
    uint32_t n = AetherFlowTableSnapshot(ctx.flows, snap, 16);
    CHECK_EQ(n, 2, "snapshot size");

    AetherFlowEntry *udpFlow = NULL, *tcpFlow = NULL;
    for (uint32_t i = 0; i < n; i++) {
        if (snap[i].proto == IPPROTO_UDP) udpFlow = &snap[i];
        if (snap[i].proto == IPPROTO_TCP) tcpFlow = &snap[i];
    }
    CHECK(udpFlow != NULL, "udp flow present");
    CHECK(tcpFlow != NULL, "tcp flow present");
    if (udpFlow) {
        CHECK_EQ(udpFlow->localPort, ntohs(a.sin_port), "udp local port");
        CHECK_EQ(udpFlow->remotePort, ntohs(b.sin_port), "udp remote port");
        CHECK_EQ(udpFlow->txPackets, 3, "udp tx packets");
        CHECK_EQ(udpFlow->rxPackets, 2, "udp rx packets");
    }
    if (tcpFlow) {
        CHECK_EQ(tcpFlow->localPort, ntohs(tcpClientAddr.sin_port), "tcp local port");
        CHECK_EQ(tcpFlow->remotePort, ntohs(tcpServerAddr.sin_port), "tcp remote port");
        CHECK_EQ(tcpFlow->txPackets, 4, "tcp tx packets");
        CHECK_EQ(tcpFlow->rxPackets, 5, "tcp rx packets");
    }

    // --- 5. BPF record walk — the 4.1.2 SIGSEGV -----------------------------
    // The kernel pads every record up to a 4-byte boundary, so for the LAST
    // record of a read() WORDALIGN(hdrlen + caplen) can be up to 3 bytes more
    // than the bytes actually present.  Before 4.1.2 the walker added that
    // padding and then evaluated `len - offset` as size_t: once offset > len
    // the subtraction wrapped to ~2^64, BOTH the loop test and the bounds
    // guard passed, and `buffer + offset` became a wild pointer — a SIGSEGV
    // every few seconds on the device (and the same function backs the 1 s
    // probe, which is why one crash reported a non-tap thread).
    //
    // The batch below ends exactly at the last record's USED bytes and is
    // placed flush against the end of a R/W page whose successor is
    // PROT_NONE, so any read past `len` is a hard fault rather than a silent
    // one.  28-byte BPF header + a 47-byte frame = 75 used bytes per record,
    // word-aligned to 76: three records → used end 227, padded end 228.
    {
        const size_t pageSz = (size_t)sysconf(_SC_PAGESIZE);
        uint8_t *area = (uint8_t *)mmap(NULL, pageSz * 2, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(area != MAP_FAILED, "mmap for the guard-page test");
        if (area != MAP_FAILED) {
            int mpr = mprotect(area + pageSz, pageSz, PROT_NONE);
            CHECK(mpr == 0, "mprotect the guard page");

            uint8_t small[128];
            size_t  smallLen = BuildFrame(small, sizeof(small), &a, &b, IPPROTO_UDP,
                                          (const uint8_t *)"hello", 5);
            CHECK(smallLen > 0, "short frame built");

            size_t used = (size_t)AETHER_BPF_HDR_SIZE + smallLen;   // 75
            size_t step = AETHER_BPF_WORDALIGN(used);               // 76
            CHECK(step > used, "fixture must end unaligned (padding needed)");

            int    copies = 3;
            size_t total  = (size_t)(copies - 1) * step + used;     // 227

            uint8_t scratch[4096];
            CHECK(BuildBPFBatch(scratch, sizeof(scratch), small, smallLen, copies) > 0,
                  "guard-page batch built");
            CHECK(total < pageSz, "batch fits in one page");

            // Flush against the guard page: buffer + len == start of PROT_NONE.
            uint8_t *tail = area + pageSz - total;
            memcpy(tail, scratch, total);

            WalkCount wc = {0};
            int got = AetherBPFIterateWithHeader(tail, total, &wc, WalkCountSink);
            CHECK_EQ(got, copies, "all records walked, none past the end");
            CHECK_EQ(wc.frames, copies, "callback invoked once per record");

            // Cut the batch inside the last record's payload: that record must
            // be dropped, not read past the end of the buffer.
            WalkCount w2 = {0};
            int got2 = AetherBPFIterateWithHeader(tail, total - 3, &w2, WalkCountSink);
            CHECK_EQ(got2, copies - 1, "truncated trailing record dropped");

            // A buffer of pure garbage must terminate instead of walking away.
            memset(area, 0xFF, pageSz);
            WalkCount w3 = {0};
            int got3 = AetherBPFIterateWithHeader(area, pageSz, &w3, WalkCountSink);
            CHECK_EQ(got3, 0, "garbage buffer yields no frames");

            munmap(area, pageSz * 2);
        }
    }

    AetherFlowTableDestroy(ctx.flows);
    close(udpA); close(udpB); close(tcpListen); close(tcpClient); close(tcpServer);

    printf("  %d checks, %d failure(s)\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
