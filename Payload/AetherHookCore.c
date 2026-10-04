//
//  AetherHookCore.c
//  AetherNet — portable BSD-socket hook core (implementation)
//

#include "AetherHookCore.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>

#include "../headers/AetherNetShared.h"

#if defined(__APPLE__)
#include <stdlib.h>          // arc4random_uniform
#endif

// ===========================================================================
// 0. Internal state
// ===========================================================================
typedef struct AetherHeldNode {
    AetherHeldPacket       pkt;
    struct AetherHeldNode *next;
} AetherHeldNode;

static pthread_mutex_t gQueueLock = PTHREAD_MUTEX_INITIALIZER;
static AetherHeldNode *gQueueHead = NULL;
static AetherHeldNode *gQueueTail = NULL;
static size_t          gQueueCount = 0;
static size_t          gQueueBytes = 0;

static AetherHookLogFn        gLogFn = NULL;
static AetherHookTargetGateFn gTargetGate = NULL;
static bool                   gDeterministic = false;
static int                    gForcedRoll = -1;
static uint32_t               gLcgState = 0xAE74E207u;
static uint64_t               gLastFlushMs = 0;
static uint32_t               gTamperSeed  = 0x5A17C0DEu;

static void AetherHookLog(const char *fmt, ...);

// ===========================================================================
// 1. Time / randomness
// ===========================================================================
uint64_t AetherHookCoreNowMs(void) {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    ts.tv_sec = (time_t)time(NULL);
    ts.tv_nsec = 0;
#endif
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static uint32_t AetherRandomBelow(uint32_t n) {
    if (n == 0) return 0;
    if (gDeterministic) {
        gLcgState = gLcgState * 1664525u + 1013904223u;
        return (gLcgState >> 8) % n;
    }
#if defined(__APPLE__)
    return (uint32_t)arc4random_uniform(n);
#else
    return (uint32_t)(random() % n);
#endif
}

uint32_t AetherHookCoreRandomPercent(void) {
    if (gForcedRoll >= 0) {
        return (uint32_t)(gForcedRoll > 99 ? 99 : gForcedRoll);
    }
    if (gDeterministic) {
        gLcgState = gLcgState * 1664525u + 1013904223u;
        return (gLcgState >> 16) % 100u;
    }
    return AetherRandomBelow(100);
}

void AetherHookCoreSetDeterministic(bool enabled) {
    gDeterministic = enabled;
    if (enabled) gLcgState = 0xAE74E207u;
}

void AetherHookCoreSetForcedRoll(int roll) { gForcedRoll = roll; }
void AetherHookCoreSetLog(AetherHookLogFn fn) { gLogFn = fn; }
void AetherHookCoreSetTargetGate(AetherHookTargetGateFn fn) { gTargetGate = fn; }

static void AetherHookLog(const char *fmt, ...) {
    if (!gLogFn) return;
    char line[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    gLogFn(line);
}

void AetherHookCoreInit(void) {
    gQueueHead = gQueueTail = NULL;
    gQueueCount = 0;
    gQueueBytes = 0;
    gLastFlushMs = AetherHookCoreNowMs();
}

void AetherHookCoreShutdown(void) { AetherHookCoreDropHeld(); }

// ===========================================================================
// 2. Socket classification
// ===========================================================================
bool AetherHookCoreSocketIsIP(int fd, bool *outIsTCP, bool *outIsUDP) {
    if (outIsTCP) *outIsTCP = false;
    if (outIsUDP) *outIsUDP = false;
    if (fd < 0) return false;

    int type = 0;
    socklen_t len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0) return false;

    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sslen) != 0) return false;
    if (ss.ss_family != AF_INET && ss.ss_family != AF_INET6) return false;

    if (type == SOCK_STREAM) { if (outIsTCP) *outIsTCP = true; return true; }
    if (type == SOCK_DGRAM)  { if (outIsUDP) *outIsUDP = true; return true; }
    return false;
}

bool AetherHookCoreSocketIsNonBlocking(int fd) {
    if (fd < 0) return false;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return (flags & O_NONBLOCK) != 0;
}

// ===========================================================================
// 3. Decision
// ===========================================================================
AetherVerdict AetherHookCoreDecide(bool isUpload,
                                   bool isTCP,
                                   bool isUDP,
                                   size_t bytes,
                                   uint32_t *outDelayUs,
                                   bool *outTamper) {
    if (outDelayUs) *outDelayUs = 0;
    if (outTamper)  *outTamper = false;

    AetherSharedState *st = AetherGetSharedState();
    AetherPolicy policy;
    AetherPolicyLoad(&policy, st);
    if (!policy.active) return AetherVerdictPass;

    // Process gate: only the attached target is intercepted.  The gate itself
    // is provided by the platform binding (bundle id + pid on iOS, pid on the
    // test host) because it needs APIs that are not portable.
    if (gTargetGate && !gTargetGate()) return AetherVerdictPass;

    uint32_t roll = AetherHookCoreRandomPercent();
    uint32_t ratio = 0;
    bool tamper = false;
    AetherVerdict v = AetherPolicyDecide(&policy, isUpload, isTCP, isUDP,
                                         roll, &ratio, &tamper);

    if (v == AetherVerdictDelay) {
        uint32_t jitterRoll = 0;
        if (policy.jitterMs > 0) {
            jitterRoll = AetherRandomBelow(policy.jitterMs * 1000u);
        }
        if (outDelayUs) *outDelayUs = AetherPolicyDelayUs(&policy, bytes, jitterRoll);
    }
    if (outTamper) *outTamper = tamper;
    return v;
}

void AetherHookCoreAccount(bool isUpload, bool isTCP, bool isUDP, size_t bytes) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return;
    if (isUpload) {
        if (isTCP) aether_atomic_fetch_add(&st->totalTCPPacketsTX, 1);
        if (isUDP) aether_atomic_fetch_add(&st->totalUDPPacketsTX, 1);
        aether_atomic_fetch_add(&st->totalBytesTX, (uint64_t)bytes);
    } else {
        if (isTCP) aether_atomic_fetch_add(&st->totalTCPPacketsRX, 1);
        if (isUDP) aether_atomic_fetch_add(&st->totalUDPPacketsRX, 1);
        aether_atomic_fetch_add(&st->totalBytesRX, (uint64_t)bytes);
    }
}

// ===========================================================================
// 4. Hold queue
// ===========================================================================
bool AetherHookCoreEnqueueTX(int fd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dst, socklen_t dstLen) {
    if (!buf || len == 0) return false;

    pthread_mutex_lock(&gQueueLock);
    if (gQueueCount >= AETHER_HELD_MAX_PACKETS ||
        (gQueueBytes + len) > AETHER_HELD_MAX_BYTES) {
        pthread_mutex_unlock(&gQueueLock);
        AetherHookLog("[hold] queue full — releasing instead of holding");
        return false;
    }

    AetherHeldNode *node = (AetherHeldNode *)calloc(1, sizeof(AetherHeldNode));
    if (!node) { pthread_mutex_unlock(&gQueueLock); return false; }

    node->pkt.payload = (uint8_t *)malloc(len);
    if (!node->pkt.payload) {
        free(node);
        pthread_mutex_unlock(&gQueueLock);
        return false;
    }
    memcpy(node->pkt.payload, buf, len);
    node->pkt.fd           = fd;
    node->pkt.flags        = flags;
    node->pkt.len          = len;
    node->pkt.enqueuedMs   = AetherHookCoreNowMs();
    if (dst && dstLen > 0 && dstLen <= (socklen_t)sizeof(node->pkt.addr)) {
        memcpy(node->pkt.addr, dst, (size_t)dstLen);
        node->pkt.addrLen = dstLen;
        node->pkt.hasAddr = true;
    }

    if (gQueueTail) gQueueTail->next = node;
    else            gQueueHead = node;
    gQueueTail = node;
    gQueueCount++;
    gQueueBytes += len;

    AetherSharedState *st = AetherGetSharedState();
    if (st) aether_atomic_store(&st->heldPacketsCount, (uint64_t)gQueueCount);
    pthread_mutex_unlock(&gQueueLock);
    return true;
}

size_t AetherHookCoreHeldCount(void) {
    pthread_mutex_lock(&gQueueLock);
    size_t n = gQueueCount;
    pthread_mutex_unlock(&gQueueLock);
    return n;
}

void AetherHookCoreFlushWith(void *ctx, AetherHookEmitFn emit) {
    pthread_mutex_lock(&gQueueLock);
    AetherHeldNode *list = gQueueHead;
    gQueueHead = gQueueTail = NULL;
    size_t flushed = gQueueCount;
    gQueueCount = 0;
    gQueueBytes = 0;
    AetherSharedState *st = AetherGetSharedState();
    if (st) aether_atomic_store(&st->heldPacketsCount, 0);
    pthread_mutex_unlock(&gQueueLock);

    while (list) {
        AetherHeldNode *next = list->next;
        if (emit) emit(ctx, &list->pkt);
        free(list->pkt.payload);
        free(list);
        list = next;
    }
    gLastFlushMs = AetherHookCoreNowMs();
    if (flushed > 0) {
        AetherHookLog("[hold] flushed %zu buffered packet(s)", flushed);
    }
}

void AetherHookCoreDropHeld(void) {
    pthread_mutex_lock(&gQueueLock);
    AetherHeldNode *list = gQueueHead;
    gQueueHead = gQueueTail = NULL;
    size_t dropped = gQueueCount;
    gQueueCount = 0;
    gQueueBytes = 0;
    AetherSharedState *st = AetherGetSharedState();
    if (st) aether_atomic_store(&st->heldPacketsCount, 0);
    pthread_mutex_unlock(&gQueueLock);

    while (list) {
        AetherHeldNode *next = list->next;
        free(list->pkt.payload);
        free(list);
        list = next;
    }
    if (dropped > 0) {
        AetherHookLog("[hold] discarded %zu buffered packet(s)", dropped);
    }
}

bool AetherHookCoreAutoFlushDue(uint64_t nowMs) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return false;
    uint32_t secs = aether_atomic_load(&st->autoFlushSeconds);
    if (secs == 0) return false;
    if (AetherHookCoreHeldCount() == 0) return false;
    if (gLastFlushMs == 0) { gLastFlushMs = nowMs; return false; }
    return (nowMs - gLastFlushMs) >= ((uint64_t)secs * 1000ULL);
}


// ===========================================================================
// 6. Send / recv paths (the whole BSD-socket lane policy)
// ===========================================================================
static volatile uint64_t gRXReleaseUntilMs = 0;

/// Hard ceiling for a stalled (held) read on a socket that has no
/// SO_RCVTIMEO of its own.  Long enough to survive a user-driven pause, short
/// enough that a bug here can never wedge the target process forever.
#define AETHER_RX_HOLD_MAX_MS 30000ULL

void AetherHookCoreReleaseRX(uint64_t windowMs) {
    gRXReleaseUntilMs = AetherHookCoreNowMs() + windowMs;
}

static bool AetherRXHoldReleased(void) {
    return AetherHookCoreNowMs() < gRXReleaseUntilMs;
}

ssize_t AetherHookCoreSend(int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *dst, socklen_t dstLen,
                           AetherSendToFn realSendTo, AetherSendFn realSend) {
    if (!realSendTo && !realSend) { errno = ENOSYS; return -1; }

    bool isTCP = false, isUDP = false;
    if (!AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP) || !buf || len == 0) {
        if (dst && realSendTo) return realSendTo(fd, buf, len, flags, dst, dstLen);
        return realSend ? realSend(fd, buf, len, flags) : -1;
    }

    uint32_t delayUs = 0;
    bool     tamper  = false;
    AetherVerdict verdict = AetherHookCoreDecide(true /* upload */, isTCP, isUDP,
                                                 len, &delayUs, &tamper);

    // --- Hold: buffer the bytes and report success ---------------------------
    if (verdict == AetherVerdictHold) {
        if (AetherHookCoreEnqueueTX(fd, buf, len, flags, dst, dstLen)) {
            AetherHookLog("[P1 TX %s %zuB] held (queue=%zu)",
                          isTCP ? "TCP" : "UDP", len, AetherHookCoreHeldCount());
            return (ssize_t)len;   // the caller must not see a failure
        }
        if (dst && realSendTo) return realSendTo(fd, buf, len, flags, dst, dstLen);
        return realSend ? realSend(fd, buf, len, flags) : -1;
    }

    // --- Drop: swallow the bytes, report success -----------------------------
    if (verdict == AetherVerdictDrop) {
        AetherSharedState *st = AetherGetSharedState();
        if (st) aether_atomic_fetch_add(&st->droppedPacketsCount, 1);
        AetherHookLog("[P1 TX %s %zuB] dropped", isTCP ? "TCP" : "UDP", len);
        return (ssize_t)len;
    }

    // --- Pass / Delay --------------------------------------------------------
    if (delayUs > 0) usleep((useconds_t)delayUs);
    AetherHookCoreAccount(true, isTCP, isUDP, len);

    const void *sendBuf = buf;
    void *scratch = NULL;
    if (tamper && len > 4) {
        scratch = malloc(len);
        if (scratch) {
            memcpy(scratch, buf, len);
            AetherHookCoreTamper(scratch, len, (uint32_t)len);
            sendBuf = scratch;
        }
    }

    ssize_t rc;
    if (dst && realSendTo) rc = realSendTo(fd, sendBuf, len, flags, dst, dstLen);
    else                   rc = realSend ? realSend(fd, sendBuf, len, flags) : -1;

    if (rc > 0 && isUDP) {
        AetherSharedState *st = AetherGetSharedState();
        uint32_t dup = st ? aether_atomic_load(&st->duplicatePacketPercent) : 0;
        if (dup > 0 && (AetherHookCoreRandomPercent() < dup)) {
            if (dst && realSendTo) realSendTo(fd, sendBuf, len, flags, dst, dstLen);
            else if (realSend)     realSend(fd, sendBuf, len, flags);
        }
    }

    if (scratch) free(scratch);
    return rc;
}

// Returns the socket's SO_RCVTIMEO in milliseconds: 0 when not set (blocking
// socket), -1 when it cannot be determined.
static int AetherHookCoreSocketRecvTimeoutMs(int fd) {
    if (fd < 0) return -1;
    struct timeval tv;
    socklen_t len = sizeof(tv);
    memset(&tv, 0, sizeof(tv));
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len) != 0) return -1;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) return 0;
    long ms = (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
    if (ms < 0) ms = 0;
    if (ms > (long)AETHER_RX_HOLD_MAX_MS) ms = (long)AETHER_RX_HOLD_MAX_MS;
    return (int)ms;
}

ssize_t AetherHookCoreRecv(int fd, void *buf, size_t len, int flags,
                           struct sockaddr *src, socklen_t *srcLen,
                           AetherRecvFromFn realRecvFrom) {
    if (!realRecvFrom) { errno = ENOSYS; return -1; }

    bool isTCP = false, isUDP = false;
    if (!AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP) || !buf || len == 0) {
        return realRecvFrom(fd, buf, len, flags, src, srcLen);
    }

    uint32_t delayUs = 0;
    bool     tamper  = false;
    AetherVerdict verdict = AetherHookCoreDecide(false /* download */, isTCP, isUDP,
                                                 len, &delayUs, &tamper);
    bool nonBlocking = AetherHookCoreSocketIsNonBlocking(fd);

    if (verdict == AetherVerdictHold) {
        if (nonBlocking) {
            // Nothing to read — the bytes stay in the kernel receive buffer
            // (which also applies TCP back-pressure on the sender).
            AetherHookLog("[P1 RX %s] held (stalled, non-blocking socket)",
                          isTCP ? "TCP" : "UDP");
            errno = EWOULDBLOCK;
            return -1;
        }
        // Blocking socket: stall the read until the user releases the hold
        // (pause -> resume, or the auto-flush watchdog) — but never longer
        // than the socket's own SO_RCVTIMEO.  Without that bound a held
        // download is indistinguishable from a hung socket: the caller would
        // sit here for the full deadline and never see its own timeout fire.
        int timeoutMs = AetherHookCoreSocketRecvTimeoutMs(fd);
        uint64_t budget = (timeoutMs > 0)
                        ? (uint64_t)timeoutMs
                        : (uint64_t)AETHER_RX_HOLD_MAX_MS;
        if (budget == 0 || budget > AETHER_RX_HOLD_MAX_MS) {
            budget = AETHER_RX_HOLD_MAX_MS;
        }
        uint64_t deadline = AetherHookCoreNowMs() + budget;
        for (;;) {
            if (AetherRXHoldReleased()) break;
            if (AetherHookCoreDecide(false, isTCP, isUDP, len, NULL, NULL) !=
                AetherVerdictHold) break;
            if (AetherHookCoreNowMs() >= deadline) {
                AetherHookLog("[P1 RX %s] held (stalled %llums, recv timeout)",
                              isTCP ? "TCP" : "UDP", (unsigned long long)budget);
                errno = EAGAIN;
                return -1;
            }
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 20) < 0 && errno != EINTR) break;
        }
    }

    if (verdict == AetherVerdictDrop) {
        // Consume and discard.  On a blocking socket this repeats until the
        // user releases us, so the app observes a stall rather than an error.
        uint64_t deadline = AetherHookCoreNowMs() + 30000ULL;
        int lastErrno = EWOULDBLOCK;
        for (;;) {
            ssize_t consumed = realRecvFrom(fd, buf, len, flags, src, srcLen);
            if (consumed > 0) {
                AetherSharedState *st = AetherGetSharedState();
                if (st) aether_atomic_fetch_add(&st->droppedPacketsCount, 1);
                AetherHookLog("[P1 RX %s %zdB] dropped",
                              isTCP ? "TCP" : "UDP", consumed);
                if (nonBlocking) break;      // one datagram per call
            } else {
                // Nothing buffered right now.  On a socket with SO_RCVTIMEO
                // this is the timeout expiring — respect it instead of
                // spinning here for the full deadline.
                if (consumed == 0) break;
                lastErrno = errno;
                break;
            }
            if (AetherHookCoreNowMs() >= deadline) break;
            if (AetherHookCoreDecide(false, isTCP, isUDP, len, NULL, NULL) !=
                AetherVerdictDrop) break;
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 50) <= 0) continue;
        }
        errno = nonBlocking ? EWOULDBLOCK : lastErrno;
        return -1;
    }

    if (delayUs > 0) usleep((useconds_t)delayUs);

    ssize_t bytes = realRecvFrom(fd, buf, len, flags, src, srcLen);
    if (bytes > 0) {
        AetherHookCoreAccount(false, isTCP, isUDP, (size_t)bytes);
        if (tamper && bytes > 4) {
            AetherHookCoreTamper(buf, (size_t)bytes, (uint32_t)bytes);
        }
    }
    return bytes;
}

// ===========================================================================
// 4b. Auto-flush watchdog
// ===========================================================================
static pthread_t  gWatchdogThread;
static bool       gWatchdogRunning = false;
static AetherHookEmitFn gWatchdogEmit = NULL;
static void            *gWatchdogCtx  = NULL;

static void *AetherWatchdogMain(void *arg) {
    (void)arg;
    while (gWatchdogRunning) {
        usleep(250000);
        AetherSharedState *st = AetherGetSharedState();
        if (!st) continue;
        if (!aether_atomic_load(&st->interceptionActive)) continue;
        if (!AetherHookCoreAutoFlushDue(AetherHookCoreNowMs())) continue;

        AetherHookLog("[watchdog] auto-flush: releasing held packets");
        AetherHookCoreFlushWith(gWatchdogCtx, gWatchdogEmit);
        AetherHookCoreReleaseRX(1500);
    }
    return NULL;
}

void AetherHookCoreStartAutoFlushWatchdog(AetherHookEmitFn emit, void *ctx) {
    if (gWatchdogRunning) return;
    gWatchdogEmit = emit;
    gWatchdogCtx  = ctx;
    gWatchdogRunning = true;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&gWatchdogThread, &attr, AetherWatchdogMain, NULL) != 0) {
        gWatchdogRunning = false;
    }
    pthread_attr_destroy(&attr);
}

// ===========================================================================
// 5. Tamper
// ===========================================================================
void AetherHookCoreTamper(void *buf, size_t len, uint32_t seed) {
    if (!buf || len == 0) return;
    gTamperSeed = gTamperSeed * 1664525u + 1013904223u + seed;
    // Skip the first 4 bytes: most protocols keep an opcode or length there,
    // and corrupting framing produces a protocol error rather than the
    // realistic single-bit payload error we are trying to simulate.
    if (len <= 4) return;
    size_t  idx = 4 + (size_t)((gTamperSeed >> 13) % (uint32_t)(len - 4));
    uint8_t bit = (uint8_t)((gTamperSeed >> 5) & 0x7u);
    ((uint8_t *)buf)[idx] ^= (uint8_t)(1u << bit);
}
