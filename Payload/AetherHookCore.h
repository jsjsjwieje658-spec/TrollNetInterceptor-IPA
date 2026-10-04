//
//  AetherHookCore.h
//  AetherNet — portable BSD-socket hook core (no ObjC, no Darwin SPI)
//
//  This is the brain behind the in-process lane (path P1/P2).  It is compiled
//  twice from the same source:
//
//    • iOS   → linked into libNetHookPayload.dylib, driven by fishhook
//              rebinding of send/sendto/sendmsg/recv/recvfrom/recvmsg/read/write
//    • host  → LD_PRELOAD shim in tests/host, driven by dlsym(RTLD_NEXT, …)
//
//  Keeping it portable means the hold queue, the probability engine, the
//  tamper logic and the auto-flush timer are covered by real traffic tests
//  on the build host instead of being "tested on the device, fingers crossed".
//

#ifndef AetherHookCore_h
#define AetherHookCore_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "../Core/L4Engine/AetherPacketCore.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AETHER_HELD_MAX_PACKETS 4096u
#define AETHER_HELD_MAX_BYTES   (8u * 1024u * 1024u)

typedef struct {
    int       fd;
    int       flags;
    uint8_t  *payload;
    size_t    len;
    uint64_t  enqueuedMs;
    uint8_t   addr[128];       // sockaddr_storage sized
    socklen_t addrLen;
    bool      hasAddr;
} AetherHeldPacket;

typedef void (*AetherHookLogFn)(const char *line);
typedef void (*AetherHookEmitFn)(void *ctx, const AetherHeldPacket *pkt);

/// Returns true when the *current process* is the attached target.
/// Supplied by the platform binding (iOS: pid + bundle id; host: pid).
typedef bool (*AetherHookTargetGateFn)(void);

// --- lifecycle -------------------------------------------------------------
void AetherHookCoreInit(void);
void AetherHookCoreShutdown(void);
void AetherHookCoreSetLog(AetherHookLogFn fn);
void AetherHookCoreSetTargetGate(AetherHookTargetGateFn fn);

/// Deterministic mode swaps the RNG for a fixed LCG so tests are reproducible.
void AetherHookCoreSetDeterministic(bool enabled);
/// Force the next N rolls (used by tests to pin probability behaviour).
void AetherHookCoreSetForcedRoll(int roll);

// --- socket classification -------------------------------------------------
bool AetherHookCoreSocketIsIP(int fd, bool *outIsTCP, bool *outIsUDP);
bool AetherHookCoreSocketIsNonBlocking(int fd);

// --- decision --------------------------------------------------------------
/// `isUpload` = true for send paths, false for recv paths.
/// Fills *outDelayUs (microseconds to sleep) and *outTamper (flip payload).
AetherVerdict AetherHookCoreDecide(bool isUpload,
                                   bool isTCP,
                                   bool isUDP,
                                   size_t bytes,
                                   uint32_t *outDelayUs,
                                   bool *outTamper);

/// Record one passing packet into the shared-memory counters.
void AetherHookCoreAccount(bool isUpload, bool isTCP, bool isUDP, size_t bytes);

// --- send / recv paths ------------------------------------------------------
//
// These own *all* of the policy for the BSD socket lane: the platform binding
// only supplies the real syscalls.  That is what makes the Linux test harness
// meaningful: it exercises the exact code that ships to the device.
typedef ssize_t (*AetherSendToFn)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t);
typedef ssize_t (*AetherSendFn)(int, const void *, size_t, int);
typedef ssize_t (*AetherRecvFromFn)(int, void *, size_t, int,
                                    struct sockaddr *, socklen_t *);

ssize_t AetherHookCoreSend(int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *dst, socklen_t dstLen,
                           AetherSendToFn realSendTo, AetherSendFn realSend);

ssize_t AetherHookCoreRecv(int fd, void *buf, size_t len, int flags,
                           struct sockaddr *src, socklen_t *srcLen,
                           AetherRecvFromFn realRecvFrom);

/// Safety watchdog: releases everything held every <autoFlushSeconds>.
/// Uses the *same* callback the platform binding uses for the ⏸ → ▶ toggle,
/// so a stalled toggle can never wedge the target's traffic forever.
void AetherHookCoreStartAutoFlushWatchdog(AetherHookEmitFn emit, void *ctx);

/// Called by the platform binding when the user releases the capture
/// (Darwin notify on iOS, SIGUSR2 in the harness).  Opens a short window in
/// which held inbound packets are delivered.
void AetherHookCoreReleaseRX(uint64_t windowMs);

// --- hold queue ------------------------------------------------------------
bool     AetherHookCoreEnqueueTX(int fd, const void *buf, size_t len, int flags,
                                 const struct sockaddr *dst, socklen_t dstLen);
size_t   AetherHookCoreHeldCount(void);
void     AetherHookCoreFlushWith(void *ctx, AetherHookEmitFn emit);
void     AetherHookCoreDropHeld(void);

/// Returns true when the safety auto-flush interval has elapsed and there is
/// something to release (caller then invokes AetherHookCoreFlushWith).
bool     AetherHookCoreAutoFlushDue(uint64_t nowMs);

// --- helpers ---------------------------------------------------------------
void     AetherHookCoreTamper(void *buf, size_t len, uint32_t seed);
uint64_t AetherHookCoreNowMs(void);
uint32_t AetherHookCoreRandomPercent(void);

#ifdef __cplusplus
}
#endif

#endif /* AetherHookCore_h */
