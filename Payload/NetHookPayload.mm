//
//  NetHookPayload.mm
//  libNetHookPayload.dylib — in-process L4 interceptor
//
//  Two lanes live here, one per user-space packet path (see README §2):
//
//   P1 — BSD socket lane
//        send / sendto / sendmsg / write  (upload)
//        recv / recvfrom / recvmsg / read (download)
//        Rebound with fishhook.  This is the path that games and cross-platform
//        engines (Unity, Unreal, POSIX libraries) still use.
//
//   P2 — libnetwork lane
//        nw_connection_send / nw_connection_receive /
//        nw_connection_receive_message
//        Since iOS 12 this is the DEFAULT path on Apple platforms: NSURLSession
//        and Network.framework build TCP/UDP inside libnetwork.dylib and hand
//        the packets to the kernel through Skywalk, never issuing a send() or
//        recv() syscall.  A hook set that only covers P1 sees literally nothing
//        for most modern apps — which is exactly why the previous revision
//        "worked" only for some targets.
//
//  All decision making lives in Payload/AetherHookCore.c (portable C, unit
//  tested on the build host); this file is only the platform binding.
//

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <Block.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <notify.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fishhook.h"
#include "AetherHookCore.h"
#include "../Core/L4Engine/AetherPacketCore.h"
#include "../Core/AetherLog.h"
#include "../headers/AetherNetShared.h"

// ===========================================================================
// 0. Originals
// ===========================================================================
static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*orig_recvmsg)(int, struct msghdr *, int) = NULL;
static ssize_t (*orig_read)(int, void *, size_t) = NULL;
static ssize_t (*orig_write)(int, const void *, size_t) = NULL;

// P2 — libnetwork.  Prototypes are expressed with void* so we do not need
// Network.framework's private headers; the ABI is pointer-sized throughout.
static void (*orig_nw_connection_send)(void *conn, void *content, void *context,
                                       bool isComplete, void *completion) = NULL;
static void (*orig_nw_connection_receive)(void *conn, uint32_t minimumIncomplete,
                                          uint32_t maximum, void *completion) = NULL;
static void (*orig_nw_connection_receive_message)(void *conn, void *completion) = NULL;

typedef void (^AetherNWSendCompletion)(void *error);
typedef void (^AetherNWReceiveCompletion)(void *content, void *context,
                                          bool isComplete, void *error);

// ===========================================================================
// 1. Target gate + logging bridge
// ===========================================================================
static AetherSharedState *gState = NULL;
static NSString          *gOwnBundleID = nil;

static bool AetherIsTargetProcess(void) {
    if (!gState) gState = AetherGetSharedState();
    if (!gState) return false;

    pid_t target = aether_atomic_load(&gState->targetPID);
    if (target > 0 && getpid() == (pid_t)target) return true;

    if (gState->targetBundleID[0] == '\0') return false;
    if (!gOwnBundleID) {
        gOwnBundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    }
    if (gOwnBundleID.length == 0) return false;
    return strncmp(gOwnBundleID.UTF8String, gState->targetBundleID,
                   sizeof(gState->targetBundleID)) == 0;
}

static void AetherHookLogLine(const char *line) {
    AetherLogDaemon(@"%s", line);
}

// ===========================================================================
// 2. P1 — BSD socket lane
// ===========================================================================

// --- the actual trampolines -------------------------------------------------
// Every one of them funnels into the portable core: the hooks are only the
// binding, the policy lives in AetherHookCore.c (which the host test harness
// compiles and exercises against real sockets).
// --- the actual trampolines -------------------------------------------------
static ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dst, socklen_t dstLen) {
    return AetherHookCoreSend(fd, buf, len, flags, dst, dstLen, orig_sendto, orig_send);
}
static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    return AetherHookCoreSend(fd, buf, len, flags, NULL, 0, orig_sendto, orig_send);
}
static ssize_t hooked_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (!orig_sendmsg) return -1;
    if (!msg) return orig_sendmsg(fd, msg, flags);

    bool isTCP = false, isUDP = false;
    if (!AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) return orig_sendmsg(fd, msg, flags);

    size_t total = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) total += msg->msg_iov[i].iov_len;
    if (total == 0) return orig_sendmsg(fd, msg, flags);

    uint32_t delayUs = 0;
    bool tamper = false;
    AetherVerdict verdict = AetherHookCoreDecide(true, isTCP, isUDP, total, &delayUs, &tamper);

    // Flatten the iovec only when we actually need a contiguous copy.
    if (verdict == AetherVerdictHold) {
        uint8_t *flat = (uint8_t *)malloc(total);
        if (flat) {
            size_t off = 0;
            for (int i = 0; i < msg->msg_iovlen; i++) {
                memcpy(flat + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                off += msg->msg_iov[i].iov_len;
            }
            const struct sockaddr *dst = (const struct sockaddr *)msg->msg_name;
            socklen_t dstLen = dst ? msg->msg_namelen : 0;
            if (AetherHookCoreEnqueueTX(fd, flat, total, flags, dst, dstLen)) {
                free(flat);
                return (ssize_t)total;
            }
            free(flat);
        }
    }
    if (verdict == AetherVerdictDrop) {
        AetherSharedState *st = AetherGetSharedState();
        if (st) aether_atomic_fetch_add(&st->droppedPacketsCount, 1);
        return (ssize_t)total;
    }
    if (delayUs > 0) usleep((useconds_t)delayUs);
    AetherHookCoreAccount(true, isTCP, isUDP, total);
    return orig_sendmsg(fd, msg, flags);
}

static ssize_t hooked_recvfrom(int fd, void *buf, size_t len, int flags,
                               struct sockaddr *src, socklen_t *srcLen) {
    return AetherHookCoreRecv(fd, buf, len, flags, src, srcLen, orig_recvfrom);
}
static ssize_t hooked_recv(int fd, void *buf, size_t len, int flags) {
    return AetherHookCoreRecv(fd, buf, len, flags, NULL, NULL, orig_recvfrom);
}
static ssize_t hooked_recvmsg(int fd, struct msghdr *msg, int flags) {
    bool isTCP = false, isUDP = false;
    if (!orig_recvmsg) return -1;
    if (!AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) return orig_recvmsg(fd, msg, flags);

    size_t total = 0;
    if (msg) {
        for (int i = 0; i < msg->msg_iovlen; i++) total += msg->msg_iov[i].iov_len;
    }
    uint32_t delayUs = 0;
    bool tamper = false;
    AetherVerdict verdict = AetherHookCoreDecide(false, isTCP, isUDP, total, &delayUs, &tamper);

    if (verdict == AetherVerdictHold && AetherHookCoreSocketIsNonBlocking(fd)) {
        AetherSharedState *st = AetherGetSharedState();
        if (st) aether_atomic_fetch_add(&st->heldPacketsCount, 1);
        errno = EWOULDBLOCK;
        return -1;
    }
    if (delayUs > 0) usleep((useconds_t)delayUs);

    ssize_t bytes = orig_recvmsg(fd, msg, flags);
    if (bytes > 0) {
        AetherHookCoreAccount(false, isTCP, isUDP, (size_t)bytes);
        if (tamper && bytes > 4) {
            // Flip a bit in the first iovec only — enough to simulate a
            // corrupted datagram without walking the whole vector.
            if (msg->msg_iovlen > 0 && msg->msg_iov[0].iov_len > 4) {
                AetherHookCoreTamper(msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len,
                                     (uint32_t)bytes);
            }
        }
    }
    return bytes;
}
static ssize_t hooked_write(int fd, const void *buf, size_t len) {
    bool isTCP = false, isUDP = false;
    if (AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) {
        return AetherHookCoreSend(fd, buf, len, 0, NULL, 0, orig_sendto, orig_send);
    }
    return orig_write ? orig_write(fd, buf, len) : -1;
}
static ssize_t hooked_read(int fd, void *buf, size_t len) {
    bool isTCP = false, isUDP = false;
    if (AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) {
        return AetherHookCoreRecv(fd, buf, len, 0, NULL, NULL, orig_recvfrom);
    }
    return orig_read ? orig_read(fd, buf, len) : -1;
}

// ===========================================================================
// 3. P2 — libnetwork lane (Network.framework / NSURLSession)
// ===========================================================================
//
// Pending completions are stored as heap Blocks inside an NSMutableArray, so
// ARC keeps the captured state (and the caller's block) alive until we decide
// to deliver it.
static NSMutableArray *gPendingSends = nil;      // @{ @"conn", @"content", @"context", @"completion" }
static NSMutableArray *gPendingReceives = nil;   // @{ @"conn", @"completion", @"min", @"max" }
static pthread_mutex_t gPendingLock = PTHREAD_MUTEX_INITIALIZER;

static void AetherNWClassify(AetherSharedState *st, bool *outIsTCP, bool *outIsUDP) {
    // libnetwork does not expose the transport of an nw_connection_t through
    // any public C accessor we can rely on.  Rather than guess and double
    // count, the user's own protocol filter defines the assumption: when they
    // ask for TCP+UDP we count it once as TCP+UDP traffic; when they narrow it
    // down, the narrow choice is what we assume (and what the counters show).
    uint8_t filter = st ? aether_atomic_load(&st->protocolFilter) : (uint8_t)AetherProtoTCPAndUDP;
    if (filter == AetherProtoTCPOnly) { *outIsTCP = true;  *outIsUDP = false; }
    else if (filter == AetherProtoUDPOnly) { *outIsTCP = false; *outIsUDP = true; }
    else { *outIsTCP = true; *outIsUDP = false; }  // counted once, as TCP
}

static size_t AetherDispatchDataSize(void *content) {
    if (!content) return 0;
    static size_t (*dispatch_data_get_size)(void *) = NULL;
    static BOOL resolved = NO;
    if (!resolved) {
        dispatch_data_get_size = (size_t (*)(void *))dlsym(RTLD_DEFAULT, "dispatch_data_get_size");
        resolved = YES;
    }
    if (dispatch_data_get_size) return dispatch_data_get_size(content);
    // Layout of dispatch_data_t is opaque; without the accessor we only know
    // "some bytes" — 1 is enough for the counters to tick.
    return 1;
}

static void AetherNWFlushLocked(void) {
    for (NSDictionary *item in gPendingSends) {
        void *conn       = [item[@"conn"] pointerValue];
        void *content    = [item[@"content"] pointerValue];
        void *context    = [item[@"context"] pointerValue];
        id   completion  = item[@"completion"];
        if (orig_nw_connection_send && conn) {
            orig_nw_connection_send(conn, content, context, true,
                                    (__bridge void *)completion);
        }
    }
    [gPendingSends removeAllObjects];

    for (NSDictionary *item in gPendingReceives) {
        void *conn      = [item[@"conn"] pointerValue];
        id   completion = item[@"completion"];
        uint32_t minLen = (uint32_t)[item[@"min"] unsignedIntValue];
        uint32_t maxLen = (uint32_t)[item[@"max"] unsignedIntValue];
        if (orig_nw_connection_receive && conn) {
            orig_nw_connection_receive(conn, minLen, maxLen, (__bridge void *)completion);
        }
    }
    [gPendingReceives removeAllObjects];
}

static void hooked_nw_connection_send(void *conn, void *content, void *context,
                                      bool isComplete, void *completion) {
    if (!orig_nw_connection_send) return;

    AetherSharedState *st = AetherGetSharedState();
    bool isTCP = false, isUDP = false;
    AetherNWClassify(st, &isTCP, &isUDP);

    size_t bytes = AetherDispatchDataSize(content);
    uint32_t delayUs = 0;
    bool tamper = false;
    AetherVerdict verdict = AetherHookCoreDecide(true, isTCP, isUDP, bytes,
                                                 &delayUs, &tamper);

    id completionObj = completion ? (__bridge id)completion : nil;
    if (!completionObj) {
        orig_nw_connection_send(conn, content, context, isComplete, completion);
        return;
    }
    id held = [completionObj copy];

    if (verdict == AetherVerdictHold) {
        pthread_mutex_lock(&gPendingLock);
        [gPendingSends addObject:@{
            @"conn":      [NSValue valueWithPointer:conn],
            @"content":   [NSValue valueWithPointer:content],
            @"context":   [NSValue valueWithPointer:context],
            @"completion": held
        }];
        if (st) aether_atomic_store(&st->heldPacketsCount,
                                    (uint64_t)[gPendingSends count] + AetherHookCoreHeldCount());
        pthread_mutex_unlock(&gPendingLock);
        AetherLogDaemon(@"[P2 TX %zuB] held at nw_connection_send", bytes);
        return;                 // nothing reaches libnetwork → nothing on the wire
    }

    if (verdict == AetherVerdictDrop) {
        AetherHookCoreAccount(true, isTCP, isUDP, bytes);
        if (st) aether_atomic_fetch_add(&st->droppedPacketsCount, 1);
        // Report success to the app, but never hand the bytes to libnetwork.
        AetherNWSendCompletion cb = (AetherNWSendCompletion)held;
        cb(NULL);
        AetherLogDaemon(@"[P2 TX %zuB] dropped", bytes);
        return;
    }

    if (delayUs > 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delayUs * NSEC_PER_USEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            AetherHookCoreAccount(true, isTCP, isUDP, bytes);
            orig_nw_connection_send(conn, content, context, isComplete,
                                    (__bridge void *)held);
        });
        return;
    }

    AetherHookCoreAccount(true, isTCP, isUDP, bytes);
    orig_nw_connection_send(conn, content, context, isComplete, completion);
}

static void hooked_nw_connection_receive(void *conn, uint32_t minimumIncomplete,
                                         uint32_t maximum, void *completion) {
    if (!orig_nw_connection_receive) return;

    AetherSharedState *st = AetherGetSharedState();
    bool isTCP = false, isUDP = false;
    AetherNWClassify(st, &isTCP, &isUDP);

    size_t bytes = (size_t)(maximum ? maximum : 65535);
    uint32_t delayUs = 0;
    bool tamper = false;
    AetherVerdict verdict = AetherHookCoreDecide(false, isTCP, isUDP, bytes,
                                                 &delayUs, &tamper);

    id completionObj = completion ? (__bridge id)completion : nil;
    if (!completionObj) {
        orig_nw_connection_receive(conn, minimumIncomplete, maximum, completion);
        return;
    }
    id held = [completionObj copy];

    if (verdict == AetherVerdictHold) {
        // Never arm the receive: libnetwork keeps the bytes in its own buffer
        // and the app simply stops seeing data.  Flush re-arms with the
        // caller's completion, so nothing is lost.
        pthread_mutex_lock(&gPendingLock);
        [gPendingReceives addObject:@{
            @"conn":       [NSValue valueWithPointer:conn],
            @"completion": held,
            @"min":        @(minimumIncomplete),
            @"max":        @(maximum)
        }];
        if (st) aether_atomic_store(&st->heldPacketsCount,
                                    (uint64_t)[gPendingReceives count] + AetherHookCoreHeldCount());
        pthread_mutex_unlock(&gPendingLock);
        AetherLogDaemon(@"[P2 RX] receive held (max=%u)", maximum);
        return;
    }

    if (verdict == AetherVerdictDrop) {
        // Consume one datagram with a sink completion, then re-arm with the
        // caller's block: the app sees "no data yet" without an error.
        AetherNWReceiveCompletion sink = ^(void *content, void *ctx, bool complete, void *err) {
            AetherHookCoreAccount(false, isTCP, isUDP, AetherDispatchDataSize(content));
            if (st) aether_atomic_fetch_add(&st->droppedPacketsCount, 1);
            AetherVerdict again = AetherHookCoreDecide(false, isTCP, isUDP, bytes, NULL, NULL);
            if (again == AetherVerdictDrop) {
                orig_nw_connection_receive(conn, minimumIncomplete, maximum,
                                           (__bridge void *)sink);
            } else {
                orig_nw_connection_receive(conn, minimumIncomplete, maximum,
                                           (__bridge void *)held);
            }
        };
        orig_nw_connection_receive(conn, minimumIncomplete, maximum,
                                   (__bridge void *)sink);
        return;
    }

    if (delayUs > 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delayUs * NSEC_PER_USEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            orig_nw_connection_receive(conn, minimumIncomplete, maximum,
                                       (__bridge void *)held);
        });
        return;
    }

    orig_nw_connection_receive(conn, minimumIncomplete, maximum, completion);
}

static void hooked_nw_connection_receive_message(void *conn, void *completion) {
    if (!orig_nw_connection_receive_message) return;
    if (!completion) {
        orig_nw_connection_receive_message(conn, completion);
        return;
    }

    AetherSharedState *st = AetherGetSharedState();
    bool isTCP = false, isUDP = false;
    AetherNWClassify(st, &isTCP, &isUDP);

    uint32_t delayUs = 0;
    bool tamper = false;
    AetherVerdict verdict = AetherHookCoreDecide(false, isTCP, isUDP, 1, &delayUs, &tamper);

    id held = [(__bridge id)completion copy];
    if (verdict == AetherVerdictHold) {
        pthread_mutex_lock(&gPendingLock);
        [gPendingReceives addObject:@{
            @"conn":       [NSValue valueWithPointer:conn],
            @"completion": held,
            @"min":        @(0u),
            @"max":        @(0u),
            @"message":    @YES
        }];
        pthread_mutex_unlock(&gPendingLock);
        return;
    }
    if (delayUs > 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delayUs * NSEC_PER_USEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            orig_nw_connection_receive_message(conn, (__bridge void *)held);
        });
        return;
    }
    orig_nw_connection_receive_message(conn, completion);
}

// ===========================================================================
// 4. Flush plumbing
// ===========================================================================
static void AetherEmitHeldPacket(void *ctx, const AetherHeldPacket *pkt) {
    (void)ctx;
    if (!pkt) return;
    if (pkt->hasAddr && orig_sendto) {
        orig_sendto(pkt->fd, pkt->payload, pkt->len, pkt->flags,
                    (const struct sockaddr *)pkt->addr, pkt->addrLen);
    } else if (orig_send) {
        orig_send(pkt->fd, pkt->payload, pkt->len, pkt->flags);
    }
}

static void AetherHandleFlush(void) {
    AetherHookCoreFlushWith(NULL, AetherEmitHeldPacket);
    pthread_mutex_lock(&gPendingLock);
    AetherNWFlushLocked();
    pthread_mutex_unlock(&gPendingLock);
    AetherHookCoreReleaseRX(1500);
}

// ===========================================================================
// 5. Constructor
// ===========================================================================
__attribute__((constructor))
static void AetherPayloadInitializer(void) {
    @autoreleasepool {
        gState = AetherGetSharedState();
        gPendingSends = [NSMutableArray array];
        gPendingReceives = [NSMutableArray array];

        AetherHookCoreInit();
        AetherHookCoreSetLog(AetherHookLogLine);
        AetherHookCoreSetTargetGate(AetherIsTargetProcess);

        // --- P1: BSD socket lane ------------------------------------------
        struct rebinding bsdHooks[] = {
            { "send",     (void *)hooked_send,     (void **)&orig_send },
            { "sendto",   (void *)hooked_sendto,   (void **)&orig_sendto },
            { "sendmsg",  (void *)hooked_sendmsg,  (void **)&orig_sendmsg },
            { "recv",     (void *)hooked_recv,     (void **)&orig_recv },
            { "recvfrom", (void *)hooked_recvfrom, (void **)&orig_recvfrom },
            { "recvmsg",  (void *)hooked_recvmsg,  (void **)&orig_recvmsg },
            { "read",     (void *)hooked_read,     (void **)&orig_read },
            { "write",    (void *)hooked_write,    (void **)&orig_write },
        };
        rebind_symbols(bsdHooks, sizeof(bsdHooks) / sizeof(bsdHooks[0]));

        // --- P2: libnetwork lane ------------------------------------------
        // rebind_symbols walks *every* loaded image, so this also patches
        // CFNetwork (NSURLSession) and the app itself when they import these.
        struct rebinding nwHooks[] = {
            { "nw_connection_send",            (void *)hooked_nw_connection_send,
              (void **)&orig_nw_connection_send },
            { "nw_connection_receive",         (void *)hooked_nw_connection_receive,
              (void **)&orig_nw_connection_receive },
            { "nw_connection_receive_message", (void *)hooked_nw_connection_receive_message,
              (void **)&orig_nw_connection_receive_message },
        };
        rebind_symbols(nwHooks, sizeof(nwHooks) / sizeof(nwHooks[0]));

        // --- Announce ------------------------------------------------------
        if (gState && AetherIsTargetProcess()) {
            aether_atomic_store(&gState->isInjected, true);
            aether_atomic_store(&gState->activeLanes,
                                (uint32_t)(AetherLaneBSDSocket |
                                           (orig_nw_connection_send ? AetherLaneLibnetwork : 0)));
            AetherLogDaemon(@"[pid %d] payload armed — P1:%s P2:%s (bundle=%@)",
                            getpid(),
                            orig_sendto ? "yes" : "no",
                            orig_nw_connection_send ? "yes" : "no",
                            gOwnBundleID ?: @"?");
        } else if (!gState) {
            // Sandboxed target, no shared state (yet).  The injector may still
            // hand us a mapping — see AetherSharedStateAdopt().
            AetherLogDaemon(@"[pid %d] payload loaded, shared state unavailable "
                            @"(sandbox) — waiting for injector handoff", getpid());
        }

        // --- Darwin notifications -----------------------------------------
        int flushToken = 0;
        notify_register_dispatch(kAetherNotifyFlushQueue, &flushToken,
                                 dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0),
                                 ^(int token) { (void)token; AetherHandleFlush(); });

        int stateToken = 0;
        notify_register_dispatch(kAetherNotifyStateChanged, &stateToken,
                                 dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
                                 ^(int token) {
            (void)token;
            AetherSharedState *st = AetherGetSharedState();
            if (!st) return;
            BOOL active = aether_atomic_load(&st->interceptionActive) && AetherIsTargetProcess();
            if (!active) {
                AetherHandleFlush();       // ⏸ → ▶ : release everything
            }
            AetherLogDaemon(@"[pid %d] capture %s (mode=%u dir=%u proto=%u)",
                            getpid(), active ? "START" : "STOP",
                            aether_atomic_load(&st->interceptMode),
                            aether_atomic_load(&st->direction),
                            aether_atomic_load(&st->protocolFilter));
        });

        int configToken = 0;
        notify_register_dispatch(kAetherNotifyConfigChanged, &configToken,
                                 dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
                                 ^(int token) {
            (void)token;
            AetherSharedState *st = AetherGetSharedState();
            if (!st || !AetherIsTargetProcess()) return;
            AetherLogDaemon(@"[pid %d] config: mode=%u latency=%ums jitter=%ums bw=%ukbps",
                            getpid(),
                            aether_atomic_load(&st->interceptMode),
                            aether_atomic_load(&st->simulatedLatencyMs),
                            aether_atomic_load(&st->simulatedJitterMs),
                            aether_atomic_load(&st->bandwidthLimitKbps));
        });

        // --- Safety auto-flush watchdog ------------------------------------
        // Lives in the portable core so the host test harness exercises the
        // exact same code.
        AetherHookCoreStartAutoFlushWatchdog(AetherEmitHeldPacket, NULL);
    }
}
