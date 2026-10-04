//
//  fake_target.c
//  AetherNet — the "app under test" for the host simulation
//
//  Two roles:
//    --server   UDP + TCP echo server (the peer, never intercepted)
//    --client   the target process: LD_PRELOAD the shim, open both a UDP and a
//               TCP flow and report what actually got through
//
//  The client prints machine readable key=value lines that run_tests.sh
//  asserts on.
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../../headers/AetherNetShared.h"
#include "host_support.h"

#define AETHER_TEST_PAYLOAD_BYTES 96

static uint64_t NowMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static int gUdpPort = 0;
static int gTcpPort = 0;
static int gCount   = 10;

// ---------------------------------------------------------------------------
// Shared protocol: "<tag>:<seq>:<payload of 'A'>"
// ---------------------------------------------------------------------------
static void MakePayload(char *buf, size_t bufLen, const char *tag, int seq) {
    snprintf(buf, bufLen, "%s:%04d:", tag, seq);
    size_t head = strlen(buf);
    for (size_t i = head; i + 1 < bufLen; i++) buf[i] = 'A';
    buf[bufLen - 1] = '\0';
}

static int PayloadIsIntact(const char *buf, size_t len, const char *tag, int seq) {
    char expected[32];
    snprintf(expected, sizeof(expected), "%s:%04d:", tag, seq);
    if (strlen(expected) > len) return 0;
    if (memcmp(buf, expected, strlen(expected)) != 0) return 0;
    for (size_t i = strlen(expected); i < len; i++) {
        if (buf[i] != 'A') return 0;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
static int RunServer(void) {
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (udp < 0 || tcp < 0) return 1;

    int one = 1;
    setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    addr.sin_port = htons((uint16_t)gUdpPort);
    if (bind(udp, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind udp"); return 1; }
    addr.sin_port = htons((uint16_t)gTcpPort);
    if (bind(tcp, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind tcp"); return 1; }
    if (listen(tcp, 8) < 0) { perror("listen"); return 1; }

    // Report the real bound ports so a driver using port 0 can find us.
    struct sockaddr_in actual;
    socklen_t alen = sizeof(actual);
    getsockname(udp, (struct sockaddr *)&actual, &alen);
    printf("SERVER udp_port=%d\n", ntohs(actual.sin_port));
    getsockname(tcp, (struct sockaddr *)&actual, &alen);
    printf("SERVER tcp_port=%d\n", ntohs(actual.sin_port));
    fflush(stdout);

    struct timeval tv;
    tv.tv_sec = 0; tv.tv_usec = 100000;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int tcpConn = -1;
    int udpSeen = 0, tcpSeen = 0;

    for (;;) {
        char buf[2048];
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        ssize_t n = recvfrom(udp, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromLen);
        if (n > 0) {
            udpSeen++;
            if (n >= 4 && memcmp(buf, "BYE", 3) == 0) {
                sendto(udp, "BYE", 3, 0, (struct sockaddr *)&from, fromLen);
                break;
            }
            sendto(udp, buf, (size_t)n, 0, (struct sockaddr *)&from, fromLen);
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // no UDP this tick — fall through to TCP
        }

        if (tcpConn < 0) {
            tv.tv_sec = 0; tv.tv_usec = 50000;
            setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            tcpConn = accept(tcp, NULL, NULL);
            if (tcpConn >= 0) {
                tv.tv_sec = 0; tv.tv_usec = 100000;
                setsockopt(tcpConn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
        }
        if (tcpConn >= 0) {
            ssize_t m = recv(tcpConn, buf, sizeof(buf), 0);
            if (m > 0) {
                tcpSeen++;
                ssize_t off = 0;
                while (off < m) {
                    ssize_t w = send(tcpConn, buf + off, (size_t)(m - off), 0);
                    if (w <= 0) break;
                    off += w;
                }
            } else if (m == 0) {
                close(tcpConn);
                tcpConn = -1;
            }
        }
    }

    printf("SERVER done udp_seen=%d tcp_seen=%d\n", udpSeen, tcpSeen);
    fflush(stdout);
    close(udp); close(tcp);
    if (tcpConn >= 0) close(tcpConn);
    return 0;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
static void PrintState(void) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return;
    printf("STATE held=%llu dropped=%llu udp_tx=%llu udp_rx=%llu tcp_tx=%llu tcp_rx=%llu bytes_tx=%llu bytes_rx=%llu\n",
           (unsigned long long)aether_atomic_load(&st->heldPacketsCount),
           (unsigned long long)aether_atomic_load(&st->droppedPacketsCount),
           (unsigned long long)aether_atomic_load(&st->totalUDPPacketsTX),
           (unsigned long long)aether_atomic_load(&st->totalUDPPacketsRX),
           (unsigned long long)aether_atomic_load(&st->totalTCPPacketsTX),
           (unsigned long long)aether_atomic_load(&st->totalTCPPacketsRX),
           (unsigned long long)aether_atomic_load(&st->totalBytesTX),
           (unsigned long long)aether_atomic_load(&st->totalBytesRX));
}

static AetherTestPolicy gPolicy = {
    .direction       = AetherDirectionBoth,
    .protocolFilter  = AetherProtoTCPAndUDP,
    .mode            = AetherModeHoldQueue,
    .captureRatio    = 100,
    .rxRatio         = 100,
    .txRatio         = 100,
    .latencyMs       = 0,
    .jitterMs        = 0,
    .bandwidthKbps   = 0,
    .autoFlushSeconds= 0,
    .duplicatePct    = 0,
};
static int gActive = 1;

static int RunClient(int holdMs, int flushAfter, int latePassMs) {
    AetherTestResetState(getpid());
    AetherTestApplyPolicy(&gPolicy);
    AetherTestSetActive(gActive != 0);

    struct timeval tv;
    tv.tv_sec = 0; tv.tv_usec = 120000;
    struct timeval lateTv;
    lateTv.tv_sec = 0; lateTv.tv_usec = (suseconds_t)(latePassMs * 1000);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)gUdpPort);

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (udp < 0 || tcp < 0) { perror("socket"); return 1; }
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(udp, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("connect udp"); return 1; }

    struct sockaddr_in tcpAddr = addr;
    tcpAddr.sin_port = htons((uint16_t)gTcpPort);
    if (connect(tcp, (struct sockaddr *)&tcpAddr, sizeof(tcpAddr)) < 0) { perror("connect tcp"); return 1; }
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint64_t t0 = NowMs();
    int udpEcho = 0, udpCorrupt = 0, tcpEcho = 0, tcpCorrupt = 0;

    // --- UDP phase ----------------------------------------------------------
    for (int i = 0; i < gCount; i++) {
        char out[AETHER_TEST_PAYLOAD_BYTES];
        char in[2048];
        MakePayload(out, sizeof(out), "UDP", i);
        ssize_t sent = send(udp, out, strlen(out), 0);
        if (sent <= 0) continue;
        ssize_t n = recv(udp, in, sizeof(in) - 1, 0);
        if (n > 0) {
            in[n] = '\0';
            if (PayloadIsIntact(in, (size_t)n, "UDP", i)) udpEcho++;
            else udpCorrupt++;
        }
    }

    // --- optional flush (mirrors the ⏸ → ▶ toggle / auto-flush) -------------
    if (flushAfter) {
        if (holdMs > 0) {
            struct timespec ts = { holdMs / 1000, (long)((holdMs % 1000) * 1000000L) };
            nanosleep(&ts, NULL);
        }
        printf("MID udp_echo_so_far=%d tcp_echo_so_far=0 ", udpEcho);
        PrintState();
        kill(getpid(), SIGUSR2);
        usleep(120000);
    }

    // --- late pass: collect anything released by the flush ------------------
    if (flushAfter || latePassMs > 0) {
        setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &lateTv, sizeof(lateTv));
        for (int i = 0; i < gCount; i++) {
            char in[2048];
            ssize_t n = recv(udp, in, sizeof(in) - 1, 0);
            if (n <= 0) break;
            in[n] = '\0';
            int seq = -1;
            if (sscanf(in, "UDP:%d:", &seq) == 1) {
                if (PayloadIsIntact(in, (size_t)n, "UDP", seq)) udpEcho++;
                else udpCorrupt++;
            }
        }
        setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    // --- TCP phase ----------------------------------------------------------
    for (int i = 0; i < gCount; i++) {
        char out[AETHER_TEST_PAYLOAD_BYTES];
        char in[AETHER_TEST_PAYLOAD_BYTES];
        MakePayload(out, sizeof(out), "TCP", i);
        ssize_t sent = send(tcp, out, strlen(out), 0);
        if (sent <= 0) continue;
        size_t got = 0;
        while (got < strlen(out)) {
            ssize_t n = recv(tcp, in + got, strlen(out) - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got == strlen(out)) {
            if (PayloadIsIntact(in, got, "TCP", i)) tcpEcho++;
            else tcpCorrupt++;
        }
        // Some protocols (hold on RX) release data late; keep the socket in a
        // consistent state by draining anything extra.
    }

    if (flushAfter) {
        setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &lateTv, sizeof(lateTv));
        kill(getpid(), SIGUSR2);
        usleep(150000);

        // TCP is a byte stream: every record that was released by the flush
        // may arrive coalesced, so accumulate and then split by record instead
        // of assuming one recv() == one message.
        char probe[AETHER_TEST_PAYLOAD_BYTES];
        MakePayload(probe, sizeof(probe), "TCP", 0);
        size_t recLen = strlen(probe);

        char stream[8192];
        size_t have = 0;
        for (int i = 0; i < gCount + 2; i++) {
            ssize_t n = recv(tcp, stream + have, sizeof(stream) - 1 - have, 0);
            if (n <= 0) break;
            have += (size_t)n;
            if (have + 1 >= sizeof(stream)) break;
        }
        stream[have] = '\0';

        for (size_t off = 0; off + recLen <= have; ) {
            if (memcmp(stream + off, "TCP:", 4) != 0) { off++; continue; }
            int seq = -1;
            if (sscanf(stream + off, "TCP:%d:", &seq) == 1) {
                if (PayloadIsIntact(stream + off, recLen, "TCP", seq)) tcpEcho++;
                else tcpCorrupt++;
            } else {
                tcpCorrupt++;
            }
            off += recLen;
        }
    }

    uint64_t elapsed = NowMs() - t0;

    printf("RESULT count=%d udp_echo=%d udp_corrupt=%d tcp_echo=%d tcp_corrupt=%d elapsed_ms=%llu\n",
           gCount, udpEcho, udpCorrupt, tcpEcho, tcpCorrupt,
           (unsigned long long)elapsed);
    PrintState();

    // Tell the server to shut down.
    char bye[8] = "BYE";
    send(udp, bye, 3, 0);
    recv(udp, bye, sizeof(bye), 0);

    close(udp);
    close(tcp);
    return 0;
}

// ---------------------------------------------------------------------------
int main(int argc, char **argv) {
    int asServer = 0, holdMs = 0, flushAfter = 0, latePassMs = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server"))      asServer = 1;
        else if (!strcmp(argv[i], "--udp-port") && i + 1 < argc) gUdpPort = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tcp-port") && i + 1 < argc) gTcpPort = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc)    gCount   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hold-ms") && i + 1 < argc)  holdMs   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--flush") )  flushAfter = 1;
        else if (!strcmp(argv[i], "--late-pass-ms") && i + 1 < argc) latePassMs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "hold"))      gPolicy.mode = AetherModeHoldQueue;
            else if (!strcmp(m, "drop")) gPolicy.mode = AetherModeDropPacket;
            else if (!strcmp(m, "delay"))gPolicy.mode = AetherModeDelayJitter;
            else if (!strcmp(m, "tamper"))gPolicy.mode = AetherModeCorruptTamper;
            else if (!strcmp(m, "pass")) gPolicy.mode = AetherModeHoldQueue, gPolicy.captureRatio = 0;
            else if (!strcmp(m, "observe")) gPolicy.mode = AetherModeObserve;
        }
        else if (!strcmp(argv[i], "--ratio") && i + 1 < argc)   gPolicy.captureRatio = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rx-ratio") && i + 1 < argc) gPolicy.rxRatio = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tx-ratio") && i + 1 < argc) gPolicy.txRatio = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) {
            const char *d = argv[++i];
            if (!strcmp(d, "up"))        gPolicy.direction = AetherDirectionUpload;
            else if (!strcmp(d, "down")) gPolicy.direction = AetherDirectionDownload;
            else                         gPolicy.direction = AetherDirectionBoth;
        }
        else if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
            const char *d = argv[++i];
            if (!strcmp(d, "udp"))       gPolicy.protocolFilter = AetherProtoUDPOnly;
            else if (!strcmp(d, "tcp"))  gPolicy.protocolFilter = AetherProtoTCPOnly;
            else                         gPolicy.protocolFilter = AetherProtoTCPAndUDP;
        }
        else if (!strcmp(argv[i], "--latency") && i + 1 < argc)  gPolicy.latencyMs = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--autoflush") && i + 1 < argc) gPolicy.autoFlushSeconds = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dup") && i + 1 < argc)      gPolicy.duplicatePct = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--inactive")) gActive = 0;
    }

    signal(SIGPIPE, SIG_IGN);

    if (asServer) return RunServer();
    return RunClient(holdMs, flushAfter, latePassMs);
}
