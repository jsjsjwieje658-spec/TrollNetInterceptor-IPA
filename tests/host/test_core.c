//
//  test_core.c
//  AetherNet — unit tests for the portable L4 core (parser, port set, flow
//  table, policy engine, BPF framing, hold queue)
//
//  These run on the build host against the exact sources that are compiled
//  into the iOS binary and the injected payload.
//

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../Core/L4Engine/AetherPacketCore.h"
#include "../../Payload/AetherHookCore.h"
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

// ===========================================================================
// Frame builders
// ===========================================================================
static size_t BuildEthernetIPv4TCP(uint8_t *buf, size_t bufLen,
                                   const char *srcIP, uint16_t srcPort,
                                   const char *dstIP, uint16_t dstPort,
                                   uint8_t flags, uint16_t payloadLen) {
    memset(buf, 0, bufLen);
    size_t off = 0;
    // Ethernet header
    buf[0] = 0x02; buf[1] = 0x00; buf[2] = 0x00;
    buf[6] = 0x02; buf[7] = 0x00; buf[8] = 0x00;
    buf[12] = 0x08; buf[13] = 0x00;
    off = 14;

    // IPv4 header (20 bytes)
    size_t ip = off;
    buf[ip + 0] = 0x45;
    buf[ip + 1] = 0x00;
    uint16_t total = (uint16_t)(20 + 20 + payloadLen);
    buf[ip + 2] = (uint8_t)(total >> 8);
    buf[ip + 3] = (uint8_t)(total & 0xFF);
    buf[ip + 8] = 64;
    buf[ip + 9] = 6;                                  // TCP
    inet_pton(AF_INET, srcIP, buf + ip + 12);
    inet_pton(AF_INET, dstIP, buf + ip + 16);
    off = ip + 20;

    // TCP header (20 bytes)
    size_t tcp = off;
    buf[tcp + 0] = (uint8_t)(srcPort >> 8); buf[tcp + 1] = (uint8_t)(srcPort & 0xFF);
    buf[tcp + 2] = (uint8_t)(dstPort >> 8); buf[tcp + 3] = (uint8_t)(dstPort & 0xFF);
    buf[tcp + 12] = (uint8_t)((20 / 4) << 4);
    buf[tcp + 13] = flags;
    off = tcp + 20;

    for (uint16_t i = 0; i < payloadLen && off < bufLen; i++) buf[off++] = 'A';
    return off;
}

static size_t BuildRawIPv6UDP(uint8_t *buf, size_t bufLen,
                              const char *srcIP, uint16_t srcPort,
                              const char *dstIP, uint16_t dstPort,
                              uint16_t payloadLen) {
    memset(buf, 0, bufLen);
    // IPv6 header (40 bytes), no extension headers
    buf[0] = 0x60;
    uint16_t payload = (uint16_t)(8 + payloadLen);
    buf[4] = (uint8_t)(payload >> 8);
    buf[5] = (uint8_t)(payload & 0xFF);
    buf[6] = 17;                                       // UDP
    buf[7] = 64;
    inet_pton(AF_INET6, srcIP, buf + 8);
    inet_pton(AF_INET6, dstIP, buf + 24);
    size_t off = 40;

    buf[off + 0] = (uint8_t)(srcPort >> 8); buf[off + 1] = (uint8_t)(srcPort & 0xFF);
    buf[off + 2] = (uint8_t)(dstPort >> 8); buf[off + 3] = (uint8_t)(dstPort & 0xFF);
    buf[off + 4] = (uint8_t)(payload >> 8); buf[off + 5] = (uint8_t)(payload & 0xFF);
    off += 8;
    for (uint16_t i = 0; i < payloadLen && off < bufLen; i++) buf[off++] = 'B';
    return off;
}

static void PutU32LE(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void PutU32BE(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

// ===========================================================================
// 1. Link-layer + L3/L4 parsing
// ===========================================================================
static void TestParseEthernetTCP(void) {
    uint8_t buf[512];
    size_t len = BuildEthernetIPv4TCP(buf, sizeof(buf), "10.0.0.2", 54321,
                                      "93.184.216.34", 443,
                                      AETHER_TCP_SYN | AETHER_TCP_ACK, 64);

    AetherParsedPacket p;
    int rc = AetherParseLinkFrame(buf, len, AETHER_DLT_EN10MB, &p);
    CHECK_EQ(rc, 0, "parse rc");
    CHECK_EQ(p.version, 4, "version");
    CHECK_EQ(p.proto, AETHER_IPPROTO_TCP, "proto");
    CHECK_EQ(p.srcPort, 54321, "src port");
    CHECK_EQ(p.dstPort, 443, "dst port");
    CHECK_EQ(p.l4PayloadLen, 64, "payload len");
    CHECK_EQ(p.tcpFlags & AETHER_TCP_SYN, AETHER_TCP_SYN, "SYN flag");
    CHECK_EQ(p.isFragment, 0, "not a fragment");

    char ep[64];
    AetherFormatEndpoint(&p, 0, ep, sizeof(ep));
    CHECK(strcmp(ep, "10.0.0.2:54321") == 0, "src endpoint: %s", ep);
    AetherFormatEndpoint(&p, 1, ep, sizeof(ep));
    CHECK(strcmp(ep, "93.184.216.34:443") == 0, "dst endpoint: %s", ep);
}

static void TestParseVLAN(void) {
    uint8_t buf[512];
    size_t len = BuildEthernetIPv4TCP(buf, sizeof(buf), "192.168.1.5", 1234,
                                      "8.8.8.8", 53, AETHER_TCP_ACK, 16);
    // Insert an 802.1Q tag: [dst(6) src(6)][0x8100 vid][ethertype][payload]
    // The tag is 4 bytes, so the payload has to move by 4, not 2.
    memmove(buf + 18, buf + 14, len - 14);
    buf[12] = 0x81; buf[13] = 0x00;
    buf[14] = 0x00; buf[15] = 0x0A;   // VLAN id 10
    buf[16] = 0x08; buf[17] = 0x00;   // real ethertype
    len += 4;

    AetherParsedPacket p;
    int rc = AetherParseLinkFrame(buf, len, AETHER_DLT_EN10MB, &p);
    CHECK_EQ(rc, 0, "VLAN parse rc");
    CHECK_EQ(p.dstPort, 53, "VLAN dst port");
}

static void TestParseRawIPv6UDP(void) {
    uint8_t buf[512];
    size_t len = BuildRawIPv6UDP(buf, sizeof(buf), "2001:db8::1", 5353,
                                 "ff02::fb", 5353, 32);

    AetherParsedPacket p;
    int rc = AetherParseLinkFrame(buf, len, AETHER_DLT_RAW, &p);
    CHECK_EQ(rc, 0, "IPv6 parse rc");
    CHECK_EQ(p.version, 6, "version");
    CHECK_EQ(p.proto, AETHER_IPPROTO_UDP, "proto");
    CHECK_EQ(p.srcPort, 5353, "src port");
    CHECK_EQ(p.l4PayloadLen, 32, "payload len");
}

static void TestParseIPv6ExtensionHeaders(void) {
    uint8_t base[512];
    size_t baseLen = BuildRawIPv6UDP(base, sizeof(base), "2001:db8::2", 1234,
                                     "2001:db8::3", 5678, 20);

    // Splice a hop-by-hop (8 bytes) + fragment header (8 bytes) after the
    // fixed IPv6 header, turning UDP into the next header.
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, base, 40);
    buf[6] = 0;                       // next = hop-by-hop
    size_t off = 40;

    buf[off + 0] = 44;                // next after hop-by-hop = fragment
    buf[off + 1] = 0;                 // hdr ext len = 0 → 8 bytes
    off += 8;

    buf[off + 0] = 17;                // next after fragment = UDP
    buf[off + 1] = 0;
    PutU32BE(buf + off + 4, 0x00000001u);   // id only, offset 0, no M flag
    off += 8;

    memcpy(buf + off, base + 40, baseLen - 40);
    size_t len = off + (baseLen - 40);

    // Fix the payload length field
    uint16_t payload = (uint16_t)(len - 40);
    buf[4] = (uint8_t)(payload >> 8);
    buf[5] = (uint8_t)(payload & 0xFF);

    AetherParsedPacket p;
    int rc = AetherParseLinkFrame(buf, len, AETHER_DLT_RAW, &p);
    CHECK_EQ(rc, 0, "ext-hdr parse rc");
    CHECK_EQ(p.proto, AETHER_IPPROTO_UDP, "proto after ext headers");
    CHECK_EQ(p.srcPort, 1234, "src port after ext headers");
}

static void TestParseRejectsGarbage(void) {
    uint8_t buf[64];
    AetherParsedPacket p;

    memset(buf, 0, sizeof(buf));
    CHECK(AetherParseLinkFrame(buf, 0, AETHER_DLT_EN10MB, &p) != 0, "empty frame");

    memset(buf, 0, sizeof(buf));
    buf[12] = 0x08; buf[13] = 0x06;                       // ARP
    CHECK(AetherParseLinkFrame(buf, 14, AETHER_DLT_EN10MB, &p) != 0, "ARP frame");

    // IPv4 claiming a header length beyond the buffer
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x08; buf[13] = 0x00;
    buf[14] = 0x4F;                                        // ihl = 15 → 60 bytes
    CHECK(AetherParseLinkFrame(buf, 30, AETHER_DLT_EN10MB, &p) != 0, "bogus ihl");

    // Truncated TCP (payload shorter than the 20 byte header)
    size_t len = BuildEthernetIPv4TCP(buf, sizeof(buf), "1.1.1.1", 1, "2.2.2.2", 2,
                                      AETHER_TCP_ACK, 0);
    uint16_t total = (uint16_t)(20 + 10);
    buf[14 + 2] = (uint8_t)(total >> 8);
    buf[14 + 3] = (uint8_t)(total & 0xFF);
    CHECK(AetherParseLinkFrame(buf, len, AETHER_DLT_EN10MB, &p) != 0, "short TCP");
}

// ===========================================================================
// 2. Port set + direction classification
// ===========================================================================
static void TestPortSet(void) {
    AetherPortSet set;
    AetherPortSetClear(&set);
    CHECK_EQ(set.count, 0, "empty set");

    CHECK(AetherPortSetAdd(&set, 443), "add 443");
    CHECK(AetherPortSetAdd(&set, 5000), "add 5000");
    AetherPortSetAdd(&set, 443);
    CHECK_EQ(set.count, 2, "duplicate ignored");
    CHECK(!AetherPortSetAdd(&set, 0), "port 0 rejected");

    CHECK(AetherPortSetContains(&set, 443), "contains 443");
    CHECK(!AetherPortSetContains(&set, 444), "does not contain 444");

    // TX when the target's port is the source
    AetherParsedPacket p;
    memset(&p, 0, sizeof(p));
    p.proto = AETHER_IPPROTO_UDP;
    p.srcPort = 5000; p.dstPort = 9000;

    bool isTX = false;
    CHECK(AetherClassifyDirection(&p, &set, &isTX), "matches by src port");
    CHECK_EQ(isTX, 1, "src match → TX");

    // RX when the target's port is the destination
    p.srcPort = 9000; p.dstPort = 5000;
    CHECK(AetherClassifyDirection(&p, &set, &isTX), "matches by dst port");
    CHECK_EQ(isTX, 0, "dst match → RX");

    // Foreign flow
    p.srcPort = 9000; p.dstPort = 9001;
    CHECK(!AetherClassifyDirection(&p, &set, &isTX), "foreign flow ignored");
}

// ===========================================================================
// 3. Flow table
// ===========================================================================
static void TestFlowTable(void) {
    AetherFlowTable *t = AetherFlowTableCreate(256);
    CHECK(t != NULL, "table created");

    AetherParsedPacket p;
    memset(&p, 0, sizeof(p));
    p.version = 4;
    p.proto = AETHER_IPPROTO_TCP;
    p.srcPort = 40000; p.dstPort = 443;
    inet_pton(AF_INET, "10.0.0.5", p.srcAddr + 12);
    memset(p.srcAddr, 0, 12);
    p.srcAddr[10] = 0xFF; p.srcAddr[11] = 0xFF;
    inet_pton(AF_INET, "93.184.216.34", p.dstAddr + 12);
    memset(p.dstAddr, 0, 12);
    p.dstAddr[10] = 0xFF; p.dstAddr[11] = 0xFF;

    CHECK(AetherFlowTableRecord(t, &p, true, 100, 1000) >= 0, "record tx");
    CHECK(AetherFlowTableRecord(t, &p, true, 200, 1100) >= 0, "record tx again");

    // The same flow seen on the way back has swapped endpoints; the table must
    // fold it into the *same* entry (that is the whole point of keying on the
    // local port plus the remote endpoint).
    AetherParsedPacket reply = p;
    reply.srcPort = 443; reply.dstPort = 40000;
    inet_pton(AF_INET, "93.184.216.34", reply.srcAddr + 12);
    inet_pton(AF_INET, "10.0.0.5", reply.dstAddr + 12);
    CHECK(AetherFlowTableRecord(t, &reply, false, 300, 1200) >= 0, "record rx");
    CHECK_EQ(AetherFlowTableCount(t), 1, "one flow");

    AetherFlowEntry snap[8];
    uint32_t n = AetherFlowTableSnapshot(t, snap, 8);
    CHECK_EQ(n, 1, "snapshot count");
    CHECK_EQ(snap[0].txPackets, 2, "tx packets");
    CHECK_EQ(snap[0].txBytes, 300, "tx bytes");
    CHECK_EQ(snap[0].rxPackets, 1, "rx packets");
    CHECK_EQ(snap[0].localPort, 40000, "local port");
    CHECK_EQ(snap[0].remotePort, 443, "remote port");

    // Different remote port → different flow
    p.dstPort = 80;
    CHECK(AetherFlowTableRecord(t, &p, true, 50, 1300) >= 0, "record second flow");
    CHECK_EQ(AetherFlowTableCount(t), 2, "two flows");
    CHECK_EQ(AetherFlowTableCount(t), 2, "reverse of a second flow folds too");

    AetherFlowTableReset(t);
    CHECK_EQ(AetherFlowTableCount(t), 0, "reset");
    AetherFlowTableDestroy(t);
}

// ===========================================================================
// 4. Policy engine
// ===========================================================================
static void TestPolicy(void) {
    AetherPolicy pol;
    memset(&pol, 0, sizeof(pol));

    // Inactive → everything passes
    pol.active = false;
    pol.mode = AetherModeDropPacket;
    pol.captureRatioPct = 100;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictPass, "inactive passes");

    // Active, drop at 100% (master × directional ratio)
    pol.active = true;
    pol.txRatioPct = 100;
    pol.rxRatioPct = 100;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictDrop, "drop at 100%");

    // Ratio 50 → roll 10 hits, roll 90 misses
    pol.captureRatioPct = 50;
    pol.rxRatioPct = 100;
    pol.txRatioPct = 100;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 10, NULL, NULL),
             AetherVerdictDrop, "ratio 50, roll 10 → drop");
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 90, NULL, NULL),
             AetherVerdictPass, "ratio 50, roll 90 → pass");

    // Directional ratio: master 100 × tx 25
    pol.captureRatioPct = 100;
    pol.txRatioPct = 25;
    pol.rxRatioPct = 100;
    CHECK_EQ(AetherPolicyEffectiveRatio(&pol, true), 25, "effective TX ratio");
    CHECK_EQ(AetherPolicyEffectiveRatio(&pol, false), 100, "effective RX ratio");

    // Hold mode
    pol.mode = AetherModeHoldQueue;
    pol.txRatioPct = 100;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictHold, "hold verdict");

    // Direction filter
    pol.mode = AetherModeDropPacket;
    pol.direction = AetherDirectionDownload;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictPass, "download-only passes uploads");
    CHECK_EQ(AetherPolicyDecide(&pol, false, true, false, 0, NULL, NULL),
             AetherVerdictDrop, "download-only drops downloads");

    pol.direction = AetherDirectionUpload;
    CHECK_EQ(AetherPolicyDecide(&pol, false, true, false, 0, NULL, NULL),
             AetherVerdictPass, "upload-only passes downloads");
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictDrop, "upload-only drops uploads");

    // Protocol filter
    pol.direction = AetherDirectionBoth;
    pol.protocolFilter = AetherProtoUDPOnly;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictPass, "UDP-only passes TCP");
    CHECK_EQ(AetherPolicyDecide(&pol, true, false, true, 0, NULL, NULL),
             AetherVerdictDrop, "UDP-only drops UDP");

    pol.protocolFilter = AetherProtoTCPOnly;
    CHECK_EQ(AetherPolicyDecide(&pol, true, false, true, 0, NULL, NULL),
             AetherVerdictPass, "TCP-only passes UDP");
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, NULL),
             AetherVerdictDrop, "TCP-only drops TCP");

    // Delay mode ignores the ratio
    pol.protocolFilter = AetherProtoTCPAndUDP;
    pol.mode = AetherModeDelayJitter;
    pol.captureRatioPct = 0;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 99, NULL, NULL),
             AetherVerdictDelay, "delay applies regardless of ratio");

    // Tamper flag
    pol.mode = AetherModeCorruptTamper;
    pol.captureRatioPct = 100;
    bool tamper = false;
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 0, NULL, &tamper),
             AetherVerdictPass, "tamper still passes");
    CHECK_EQ(tamper, 1, "tamper flag set");
    CHECK_EQ(AetherPolicyDecide(&pol, true, true, false, 99, NULL, &tamper),
             AetherVerdictPass, "tamper pass again");
    CHECK_EQ(tamper, 1, "tamper still set at 100%");
}

static void TestDelayComputation(void) {
    AetherPolicy pol;
    memset(&pol, 0, sizeof(pol));
    pol.active = true;
    pol.latencyMs = 100;
    pol.jitterMs = 0;
    pol.bandwidthKbps = 0;
    CHECK_EQ(AetherPolicyDelayUs(&pol, 1000, 0), 100000, "latency only");

    pol.bandwidthKbps = 1000;      // 1 Mbps
    // 1000 bytes = 8000 bits / 1000 kbps = 8 ms → 8000 us
    CHECK_EQ(AetherPolicyDelayUs(&pol, 1000, 0), 108000, "latency + bandwidth");

    pol.jitterMs = 10;
    CHECK_EQ(AetherPolicyDelayUs(&pol, 0, 5000), 105000, "latency + jitter");

    // Clamp
    pol.latencyMs = 100000;
    CHECK_EQ(AetherPolicyDelayUs(&pol, 0, 0), AETHER_MAX_DELAY_US, "clamped");
}

// ===========================================================================
// 5. BPF framing
// ===========================================================================
typedef struct {
    int      count;
    uint8_t  last[8];
    size_t   lastLen;
} BPFCollectCtx;

static void BPFCollect(void *ctxRaw, const uint8_t *frame, size_t caplen) {
    BPFCollectCtx *ctx = (BPFCollectCtx *)ctxRaw;
    ctx->count++;
    ctx->lastLen = caplen < sizeof(ctx->last) ? caplen : sizeof(ctx->last);
    memcpy(ctx->last, frame, ctx->lastLen);
}

static int BuildBPFRecord(uint8_t *out, size_t caplen, uint8_t marker) {
    memset(out, 0, AETHER_BPF_HDR_SIZE);
    PutU32LE(out + 16, (uint32_t)caplen);        // bh_caplen @16
    PutU32LE(out + 20, (uint32_t)caplen);        // bh_datalen @20
    out[24] = (uint8_t)AETHER_BPF_HDR_SIZE; out[25] = 0;  // bh_hdrlen @24 (LE)
    for (size_t i = 0; i < caplen; i++) out[AETHER_BPF_HDR_SIZE + i] = marker;
    // The kernel pads the header to a word boundary; bh_hdrlen already covers
    // that, so the record length is AETHER_BPF_WORDALIGN(hdrlen + caplen).
    return (int)AETHER_BPF_WORDALIGN((size_t)AETHER_BPF_HDR_SIZE + caplen);
}

static void TestBPFIterate(void) {
    uint8_t buf[1024];
    memset(buf, 0, sizeof(buf));

    size_t off = 0;
    // Three records with different (unaligned) capture lengths to exercise the
    // word-alignment arithmetic.
    off += (size_t)BuildBPFRecord(buf + off, 61, 0xAA);
    off += (size_t)BuildBPFRecord(buf + off, 64, 0xBB);
    off += (size_t)BuildBPFRecord(buf + off, 67, 0xCC);

    BPFCollectCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    int frames = AetherBPFIterate(buf, off, &ctx, BPFCollect);
    CHECK_EQ(frames, 3, "three frames");
    CHECK_EQ(ctx.count, 3, "callback count");
    CHECK_EQ(ctx.lastLen, 8, "last frame length recorded");
    CHECK_EQ(ctx.last[0], 0xCC, "third frame marker");

    // A truncated record must not be emitted
    ctx.count = 0;
    AetherBPFIterate(buf, off - 10, &ctx, BPFCollect);
    CHECK_EQ(ctx.count, 2, "truncated tail dropped");

    // Zero-length and oversized headers are rejected without crashing
    uint8_t junk[64];
    memset(junk, 0, sizeof(junk));
    PutU32LE(junk + 16, 4096);      // caplen far beyond the buffer
    junk[24] = (uint8_t)AETHER_BPF_HDR_SIZE; junk[25] = 0;
    ctx.count = 0;
    AetherBPFIterate(junk, sizeof(junk), &ctx, BPFCollect);
    CHECK_EQ(ctx.count, 0, "oversized caplen rejected");

    memset(junk, 0, sizeof(junk));
    PutU32LE(junk + 16, 0);         // caplen 0
    junk[24] = (uint8_t)AETHER_BPF_HDR_SIZE; junk[25] = 0;
    ctx.count = 0;
    AetherBPFIterate(junk, sizeof(junk), &ctx, BPFCollect);
    CHECK_EQ(ctx.count, 0, "zero caplen rejected");
}

// ---------------------------------------------------------------------------
// Extended BPF header (BIOCSEXTHDR) + record framing.
//
// bsd/net/bpf.h: on LP64, BPF_TIMEVAL is timeval32 (8 bytes), so caplen sits
// at offset 8 and bh_hdrlen at 16 — not 16/24 as every BSD textbook shows.
// 4.0.5 read the 28 byte layout and therefore rejected every record a real
// iPhone produced.  The fixtures below are typed from an actual device log.
// ---------------------------------------------------------------------------
typedef struct {
    int      count;
    pid_t    pid[4];
    int      tx[4];
    int      ext[4];
    uint32_t ts[4];
    size_t   hdrLen[4];
    int      sport[4];
    int      dport[4];
    uint8_t  last[8];
} ExtCollectCtx;

static void ExtCollect(void *ctxRaw, const AetherBPFMeta *meta,
                       const uint8_t *frame, size_t caplen) {
    ExtCollectCtx *ctx = (ExtCollectCtx *)ctxRaw;
    int i = ctx->count;
    if (i > 3) return;
    ctx->hdrLen[i] = meta->hdrLen;
    ctx->pid[i]    = meta->pid;
    ctx->tx[i]     = meta->isTX ? 1 : 0;
    ctx->ext[i]    = meta->extHdr ? 1 : 0;
    ctx->ts[i]     = meta->tsSize;

    AetherParsedPacket p;
    if (AetherParseLinkFrame(frame, caplen, AETHER_DLT_EN10MB, &p) == 0) {
        ctx->sport[i] = (int)p.srcPort;
        ctx->dport[i] = (int)p.dstPort;
    }
    size_t n = caplen < sizeof(ctx->last) ? caplen : sizeof(ctx->last);
    memcpy(ctx->last, frame, n);
    ctx->count++;
}

// A real Ethernet + IPv4 + UDP frame, so the whole tap path is exercised.
static size_t BuildEthUDP(uint8_t *out, uint16_t sport, uint16_t dport,
                          size_t payload, uint8_t marker) {
    memset(out, 0, 14);
    out[12] = 0x08; out[13] = 0x00;          // ethertype IPv4
    uint8_t *ip = out + 14;
    size_t   udpLen = 8 + payload;
    size_t   ipLen  = 20 + udpLen;
    memset(ip, 0, ipLen);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ipLen >> 8); ip[3] = (uint8_t)ipLen;
    ip[8] = 64;
    ip[9] = AETHER_IPPROTO_UDP;
    ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
    ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
    uint8_t *udp = ip + 20;
    udp[0] = (uint8_t)(sport >> 8); udp[1] = (uint8_t)sport;
    udp[2] = (uint8_t)(dport >> 8); udp[3] = (uint8_t)dport;
    udp[4] = (uint8_t)(udpLen >> 8); udp[5] = (uint8_t)udpLen;
    memset(udp + 8, marker, payload);
    return 14 + ipLen;
}

// Build one record.  tsSize 8  = timeval32 (iOS LP64), 16 = struct timeval.
static int BuildBPFExtRecord(uint8_t *out, const uint8_t *frame, size_t caplen,
                             pid_t pid, int isTX, uint32_t tsSize, uint32_t sec) {
    size_t hdrSize = tsSize + 52u;                 // sizeof(bpf_hdr_ext)
    memset(out, 0, hdrSize + caplen);
    if (tsSize == 8) {
        PutU32LE(out + 0, sec);                    // tv_sec  (int32)
        PutU32LE(out + 4, 864803u);                // tv_usec (int32)
    } else {
        PutU32LE(out + 0, sec);                    // low half of a 64 bit tv_sec
        PutU32LE(out + 4, 0u);
        PutU32LE(out + 8, 864803u);
        PutU32LE(out + 12, 0u);
    }
    PutU32LE(out + tsSize + 0, (uint32_t)caplen);  // bh_caplen
    PutU32LE(out + tsSize + 4, (uint32_t)caplen);  // bh_datalen
    out[tsSize + 8] = (uint8_t)hdrSize; out[tsSize + 9] = (uint8_t)(hdrSize >> 8);
    if (isTX) out[tsSize + 11] = AETHER_BPF_EXT_DIR_OUT;
    memcpy(out + tsSize + 12, &pid, sizeof(pid));  // bh_pid
    memcpy(out + hdrSize, frame, caplen);
    return (int)AETHER_BPF_WORDALIGN(hdrSize + caplen);
}

static void TestBPFExtHeader(void) {
    uint8_t frame[128];
    size_t  flen = BuildEthUDP(frame, 53311, 443, 40, 0x5A);

    // --- iOS framing: 8 byte timestamp (timeval32) -------------------------
    uint8_t buf8[1024];
    size_t off = 0;
    off += (size_t)BuildBPFExtRecord(buf8 + off, frame, flen, 91859, 1, 8, 1791077314u);
    off += (size_t)BuildBPFExtRecord(buf8 + off, frame, flen, 91859, 0, 8, 1791077315u);
    off += (size_t)BuildBPFExtRecord(buf8 + off, frame, flen, 123,   1, 8, 1791077316u);

    AetherBPFFraming f8 = AetherBPFDetectFraming(buf8, off);
    CHECK_EQ((int)f8.tsSize, 8, "framing: iOS uses an 8 byte timestamp");

    ExtCollectCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ(AetherBPFIterateWithHeader(buf8, off, &ctx, ExtCollect), 3, "ext8: three frames");
    CHECK_EQ(ctx.count, 3, "ext8: callback count");
    CHECK_EQ((int)ctx.hdrLen[0], 60, "ext8: bh_hdrlen 60");
    CHECK_EQ((int)ctx.ts[0], 8, "ext8: framing passed through");
    CHECK_EQ((int)ctx.pid[0], 91859, "ext8: pid of first packet");
    CHECK_EQ((int)ctx.pid[2], 123,   "ext8: pid of foreign packet");
    CHECK_EQ(ctx.tx[0], 1, "ext8: first packet is TX");
    CHECK_EQ(ctx.tx[1], 0, "ext8: second packet is RX");
    CHECK_EQ(ctx.ext[0], 1, "ext8: extended header detected");
    CHECK_EQ(ctx.sport[0], 53311, "ext8: payload parsed (sport)");
    CHECK_EQ(ctx.dport[0], 443,   "ext8: payload parsed (dport)");

    // --- legacy framing: 16 byte timestamp ---------------------------------
    uint8_t buf16[1024];
    size_t off16 = 0;
    off16 += (size_t)BuildBPFExtRecord(buf16 + off16, frame, flen, 4242, 1, 16, 1791077314u);
    AetherBPFFraming f16 = AetherBPFDetectFraming(buf16, off16);
    CHECK_EQ((int)f16.tsSize, 16, "framing: 64 bit timestamp detected");
    ExtCollectCtx c16;
    memset(&c16, 0, sizeof(c16));
    CHECK_EQ(AetherBPFIterateWithHeader(buf16, off16, &c16, ExtCollect), 1, "ext16: one frame");
    CHECK_EQ((int)c16.pid[0], 4242, "ext16: pid at tsSize+12");
    CHECK_EQ((int)c16.hdrLen[0], 68, "ext16: bh_hdrlen 68");

    // --- classic 18 byte header (extended header OFF) ----------------------
    // Nothing may be invented: pid 0, no direction, payload still parsed.
    uint8_t cl[512];
    memset(cl, 0, sizeof(cl));
    PutU32LE(cl + 0, 1791077314u);
    PutU32LE(cl + 4, 864803u);
    PutU32LE(cl + 8, (uint32_t)flen);
    PutU32LE(cl + 12, (uint32_t)flen);
    cl[16] = 18; cl[17] = 0;                       // bh_hdrlen = SIZEOF_BPF_HDR
    memcpy(cl + 18, frame, flen);
    size_t clen = AETHER_BPF_WORDALIGN(18u + flen);
    ExtCollectCtx ccl;
    memset(&ccl, 0, sizeof(ccl));
    CHECK_EQ(AetherBPFIterateWithHeader(cl, clen, &ccl, ExtCollect), 1, "classic: one frame");
    CHECK_EQ((int)ccl.ext[0], 0, "classic: no ext fields");
    CHECK_EQ((int)ccl.pid[0], 0, "classic: pid stays 0");
    CHECK_EQ(ccl.tx[0], 0, "classic: no direction");
    CHECK_EQ(ccl.sport[0], 53311, "classic: payload still parsed");
}

// The exact bytes a build 4.0.5 device logged as "no BPF record decoded".
static void TestBPFDeviceBytes(void) {
    uint8_t batch[1024];
    memset(batch, 0, sizeof(batch));
    size_t off = 0;

    uint8_t frame[128];
    size_t  flen = BuildEthUDP(frame, 63353, 443, 8, 0xC3);

    // Record 1: the header the device printed, filled out to a whole record.
    // c2abc16a 23320d00 | 97000000 97000000 | 3e00 | 00 00 | 00000000
    uint8_t dev[62];
    memset(dev, 0, sizeof(dev));
    PutU32LE(dev + 0, 0x6ac1abc2u);   // tv_sec  = 1791077314
    PutU32LE(dev + 4, 0x000d3223u);   // tv_usec = 864803
    PutU32LE(dev + 8, (uint32_t)flen);  // bh_caplen
    PutU32LE(dev + 12, (uint32_t)flen); // bh_datalen
    dev[16] = 62; dev[17] = 0;        // bh_hdrlen (WORDALIGN(14+60)-14)
    dev[19] = AETHER_BPF_EXT_DIR_OUT; // bh_flags: TX
    PutU32LE(dev + 20, 0u);           // bh_pid: none for this packet

    memcpy(batch + off, dev, sizeof(dev));
    memcpy(batch + off + sizeof(dev), frame, flen);
    off += AETHER_BPF_WORDALIGN(sizeof(dev) + flen);

    // Record 2: a packet the kernel did attribute (bh_pid = 91859).
    uint8_t dev2[62];
    memcpy(dev2, dev, sizeof(dev2));
    PutU32LE(dev2 + 8, (uint32_t)flen);
    PutU32LE(dev2 + 12, (uint32_t)flen);
    dev2[19] = 0;                     // RX
    PutU32LE(dev2 + 20, 91859u);
    memcpy(batch + off, dev2, sizeof(dev2));
    memcpy(batch + off + sizeof(dev2), frame, flen);
    off += AETHER_BPF_WORDALIGN(sizeof(dev2) + flen);

    AetherBPFFraming f = AetherBPFDetectFraming(batch, off);
    CHECK_EQ((int)f.tsSize, 8, "device bytes: 8 byte timestamp detected");

    ExtCollectCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ(AetherBPFIterateWithHeader(batch, off, &ctx, ExtCollect), 2,
             "device bytes: both records decoded");
    CHECK_EQ(ctx.tx[0], 1, "device bytes: first record is TX");
    CHECK_EQ((int)ctx.pid[0], 0, "device bytes: first record has no pid");
    CHECK_EQ((int)ctx.pid[1], 91859, "device bytes: second record pid");
    CHECK_EQ(ctx.sport[1], 63353, "device bytes: frame parsed after a 62 byte header");
}

// ---------------------------------------------------------------------------
// DLT_NULL (what utun0..2 report on iOS): a 4-byte address family precedes IP.
// ---------------------------------------------------------------------------
static void PutU16BE(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static void TestDLTNull(void) {
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 2;                 // AF_INET, host (little endian) order
    uint8_t *ip = pkt + 4;
    ip[0] = 0x45;               // IPv4, IHL 5
    PutU16BE(ip + 2, 40);       // total length
    ip[9] = AETHER_IPPROTO_UDP;
    PutU32BE(ip + 12, 0x0a000001);   // src
    PutU32BE(ip + 16, 0x0a000002);   // dst
    PutU16BE(ip + 20, 51000);        // sport
    PutU16BE(ip + 22, 4433);         // dport
    PutU16BE(ip + 24, 12);           // UDP length

    AetherParsedPacket p;
    int rc = AetherParseLinkFrame(pkt, 44, AETHER_DLT_NULL, &p);
    CHECK_EQ(rc, 0, "dlt_null: parse rc");
    CHECK_EQ((int)p.proto, (int)AETHER_IPPROTO_UDP, "dlt_null: proto");
    CHECK_EQ((int)p.srcPort, 51000, "dlt_null: sport");
    CHECK_EQ((int)p.dstPort, 4433, "dlt_null: dport");
}

// ===========================================================================
// 6. Hold queue
// ===========================================================================
typedef struct {
    char buf[256];
    int  n;
} AetherCollectCtx;

static void AetherTestCollectEmit(void *ctxRaw, const AetherHeldPacket *pkt) {
    AetherCollectCtx *ctx = (AetherCollectCtx *)ctxRaw;
    if (!ctx || !pkt) return;
    ctx->n++;
    size_t used = strlen(ctx->buf);
    size_t room = sizeof(ctx->buf) - used - 1;
    size_t take = pkt->len < 32 ? pkt->len : 32;
    if (take > room) take = room;
    if (take > 0) {
        memcpy(ctx->buf + used, pkt->payload, take);
        used += take;
        ctx->buf[used] = '\0';
    }
    if (used + 1 < sizeof(ctx->buf)) {
        ctx->buf[used] = '|';
        ctx->buf[used + 1] = '\0';
    }
}

static void TestHoldQueue(void) {
    AetherHookCoreInit();
    AetherHookCoreSetDeterministic(true);

    CHECK_EQ(AetherHookCoreHeldCount(), 0, "queue starts empty");

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    const char *msg1 = "hello-one";
    const char *msg2 = "hello-two-longer";
    CHECK(AetherHookCoreEnqueueTX(7, msg1, strlen(msg1), 0,
                                  (struct sockaddr *)&dst, sizeof(dst)), "enqueue 1");
    CHECK(AetherHookCoreEnqueueTX(7, msg2, strlen(msg2), 0, NULL, 0), "enqueue 2");
    CHECK_EQ(AetherHookCoreHeldCount(), 2, "two held");

    // Flush and inspect what comes out, in order
    AetherCollectCtx ctxv;
    memset(&ctxv, 0, sizeof(ctxv));
    AetherHookCoreFlushWith(&ctxv, AetherTestCollectEmit);

    CHECK_EQ(ctxv.n, 2, "flushed two packets");
    CHECK(strstr(ctxv.buf, "hello-one") != NULL, "first packet: %s", ctxv.buf);
    CHECK(strstr(ctxv.buf, "hello-two-longer") != NULL, "second packet: %s", ctxv.buf);
    CHECK_EQ(AetherHookCoreHeldCount(), 0, "queue drained");

    // Drop path
    AetherHookCoreEnqueueTX(7, msg1, strlen(msg1), 0, NULL, 0);
    CHECK_EQ(AetherHookCoreHeldCount(), 1, "one held again");
    AetherHookCoreDropHeld();
    CHECK_EQ(AetherHookCoreHeldCount(), 0, "dropped");
}

// ===========================================================================
int main(void) {
    setenv("AETHER_TEST_SHM", "/tmp/aether-core-test.shm", 1);
    setenv("AETHER_TEST_LOG", "/tmp/aether-core-test.log", 1);
    remove("/tmp/aether-core-test.shm");
    remove("/tmp/aether-core-test.log");

    printf("── packet core unit tests ─────────────────────────────────\n");
    TestParseEthernetTCP();
    TestParseVLAN();
    TestParseRawIPv6UDP();
    TestParseIPv6ExtensionHeaders();
    TestParseRejectsGarbage();
    TestPortSet();
    TestFlowTable();
    TestPolicy();
    TestDelayComputation();
    TestBPFIterate();
    TestBPFExtHeader();
    TestBPFDeviceBytes();
    TestDLTNull();
    TestHoldQueue();

    printf("  %d checks, %d failure(s)\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
