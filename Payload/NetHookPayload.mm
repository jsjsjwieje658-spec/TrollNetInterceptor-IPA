//
//  NetHookPayload.mm
//  libNetHookPayload.dylib — Injected L4 (TCP & UDP) Socket Interceptor
//
//  Hooks BSD Socket APIs inside target PID:
//    - Upload (TX):   send(), sendto(), sendmsg()
//    - Download (RX): recv(), recvfrom(), recvmsg()
//

#import <Foundation/Foundation.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <notify.h>
#include <pthread.h>
#include <vector>
#include <deque>
#include "fishhook.h"
#include "../headers/AetherNetShared.h"
#import "../Core/AetherLog.h"

// Original function pointers
static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*orig_recvmsg)(int, struct msghdr *, int) = NULL;

// Queued outbound packet structure for Hold/Freeze mode
struct HeldOutboundPacket {
    int sockfd;
    std::vector<uint8_t> payload;
    int flags;
    bool hasDestAddr;
    struct sockaddr_storage destAddr;
    socklen_t addrLen;
    uint64_t timestampMs;
};

static pthread_mutex_t gQueueMutex = PTHREAD_MUTEX_INITIALIZER;
static std::deque<HeldOutboundPacket> gHeldTXQueue;
static AetherSharedState *gState = NULL;

static inline uint64_t NowMilliseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

// Inspects whether file descriptor is an IPv4/IPv6 TCP (SOCK_STREAM) or UDP (SOCK_DGRAM) socket
static bool InspectSocketProtocol(int fd, bool *outIsTCP, bool *outIsUDP) {
    *outIsTCP = false;
    *outIsUDP = false;

    int sockType = 0;
    socklen_t optLen = sizeof(sockType);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sockType, &optLen) != 0) {
        return false;
    }

    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &addrLen) != 0) {
        return false;
    }

    if (addr.ss_family != AF_INET && addr.ss_family != AF_INET6) {
        return false; // Ignore UNIX domain / local IPC sockets so UI/Mach stays responsive
    }

    if (sockType == SOCK_STREAM) {
        *outIsTCP = true;
        return true;
    } else if (sockType == SOCK_DGRAM) {
        *outIsUDP = true;
        return true;
    }
    return false;
}

// The tweak is injected into EVERY UIKit process by ellekit. Only capture
// traffic when THIS process is the attached target (pid match, or bundle-id
// match so capture survives a target relaunch which changes the pid).
static NSString *gOwnBundleID = nil;
static bool AetherOwnBundleMatchesTarget(void) {
    if (!gState || gState->targetBundleID[0] == '\0') return false;
    if (!gOwnBundleID) gOwnBundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (gOwnBundleID.length == 0) return false;
    return strncmp(gOwnBundleID.UTF8String, gState->targetBundleID,
                   sizeof(gState->targetBundleID)) == 0;
}

static bool AetherHookGatesPass(void) {
    if (!gState) gState = AetherGetSharedState();
    if (!gState) return false;
    pid_t tgt = aether_atomic_load(&gState->targetPID);
    if (tgt > 0 && getpid() == tgt) return true;
    return AetherOwnBundleMatchesTarget();
}

// Checks direction + protocol filters only (no capture-ratio probability).
// Used for Delay/Jitter network simulation which should apply to ALL packets,
// not just the fraction selected by captureRatioPercent.
static bool AetherDirectionProtoMatch(bool isUpload, bool isTCP, bool isUDP) {
    if (!gState) gState = AetherGetSharedState();
    if (!gState) return false;

    if (!aether_atomic_load(&gState->interceptionActive)) return false;
    if (!AetherHookGatesPass()) return false;

    uint8_t dir = aether_atomic_load(&gState->direction);
    if (dir == AetherDirectionDownload && isUpload) return false;
    if (dir == AetherDirectionUpload && !isUpload) return false;

    uint8_t proto = aether_atomic_load(&gState->protocolFilter);
    if (proto == AetherProtoUDPOnly && !isUDP) return false;
    if (proto == AetherProtoTCPOnly && !isTCP) return false;

    return true;
}

// Determines whether a packet should be intercepted (Hold/Drop) based on capture probability
static bool ShouldInterceptPacket(bool isUpload, bool isTCP, bool isUDP, uint32_t *outEffectiveRatio) {
    if (!gState) gState = AetherGetSharedState();
    if (!gState) return false;

    if (!aether_atomic_load(&gState->interceptionActive)) {
        return false;
    }

    if (!AetherHookGatesPass()) {
        return false; // this process is not the attached target
    }

    // 1. Check Direction Filter (Both / Download Only / Upload Only)
    uint8_t dir = aether_atomic_load(&gState->direction);
    if (dir == AetherDirectionDownload && isUpload) return false;
    if (dir == AetherDirectionUpload && !isUpload) return false;

    // 2. Check Protocol Filter (TCP+UDP / UDP Only / TCP Only)
    uint8_t proto = aether_atomic_load(&gState->protocolFilter);
    if (proto == AetherProtoUDPOnly && !isUDP) return false;
    if (proto == AetherProtoTCPOnly && !isTCP) return false;

    // 3. Compute directional capture probability (0 - 100%)
    uint32_t masterRatio = aether_atomic_load(&gState->captureRatioPercent);
    uint32_t dirRatio = isUpload
        ? aether_atomic_load(&gState->uploadHoldPercent)
        : aether_atomic_load(&gState->downloadHoldPercent);

    uint32_t effectiveRatio = (masterRatio * dirRatio) / 100U;
    if (outEffectiveRatio) *outEffectiveRatio = effectiveRatio;

    if (effectiveRatio >= 100) return true;
    if (effectiveRatio == 0) return false;

    uint32_t roll = arc4random_uniform(100);
    return (roll < effectiveRatio);
}

// Applies configured latency + jitter + bandwidth throttle
static void ApplyNetworkConditioningDelay(size_t packetBytes) {
    if (!gState) return;
    uint32_t baseLatencyMs = aether_atomic_load(&gState->simulatedLatencyMs);
    uint32_t jitterMs = aether_atomic_load(&gState->simulatedJitterMs);
    uint32_t bwLimitKbps = aether_atomic_load(&gState->bandwidthLimitKbps);

    uint32_t totalSleepUs = baseLatencyMs * 1000U;
    if (jitterMs > 0) {
        totalSleepUs += arc4random_uniform(jitterMs * 1000U);
    }
    if (bwLimitKbps > 0 && packetBytes > 0) {
        // Serialization delay = (bits / kbps) ms
        uint32_t bwDelayUs = (uint32_t)(((uint64_t)packetBytes * 8000ULL) / bwLimitKbps);
        totalSleepUs += bwDelayUs;
    }
    if (totalSleepUs > 0 && totalSleepUs <= 3000000U) {
        usleep(totalSleepUs);
    }
}

// Flushes all held outbound packets when user switches Floating Button from ⏸ (Pause) -> ▶ (Play)
static void FlushHeldPacketQueue(void) {
    pthread_mutex_lock(&gQueueMutex);
    std::deque<HeldOutboundPacket> toFlush;
    toFlush.swap(gHeldTXQueue);
    if (gState) {
        aether_atomic_store(&gState->heldPacketsCount, 0);
    }
    pthread_mutex_unlock(&gQueueMutex);

    for (const auto &pkt : toFlush) {
        if (pkt.hasDestAddr && orig_sendto) {
            orig_sendto(pkt.sockfd, pkt.payload.data(), pkt.payload.size(), pkt.flags,
                        (const struct sockaddr *)&pkt.destAddr, pkt.addrLen);
        } else if (orig_send) {
            orig_send(pkt.sockfd, pkt.payload.data(), pkt.payload.size(), pkt.flags);
        }
    }
}

// ============================================================================
// Hooked Outbound (Upload / TX) Socket Functions
// ============================================================================
static ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dest_addr, socklen_t addrlen) {
    bool isTCP = false, isUDP = false;
    if (InspectSocketProtocol(sockfd, &isTCP, &isUDP) && gState) {
        if (isTCP) aether_atomic_fetch_add(&gState->totalTCPPacketsTX, 1);
        if (isUDP) aether_atomic_fetch_add(&gState->totalUDPPacketsTX, 1);
        aether_atomic_fetch_add(&gState->totalBytesTX, len);

        uint8_t mode = aether_atomic_load(&gState->interceptMode);

        // Delay/Jitter network simulation applies to ALL matching packets
        // (direction + protocol filters), NOT just the capture-ratio subset.
        if (mode == AetherModeDelayJitter && AetherDirectionProtoMatch(true, isTCP, isUDP)) {
            ApplyNetworkConditioningDelay(len);
            AetherLogDaemon(@"[TX %s %zuB] delay+jitter applied", isTCP ? "TCP" : "UDP", len);
        }

        uint32_t ratio = 0;
        if (ShouldInterceptPacket(true /* isUpload */, isTCP, isUDP, &ratio)) {
            if (mode == AetherModeHoldQueue) {
                // Buffer outbound packet in memory queue while ⏸ is active
                pthread_mutex_lock(&gQueueMutex);
                if (gHeldTXQueue.size() < 4096 && buf != NULL && len > 0) {
                    HeldOutboundPacket held;
                    held.sockfd = sockfd;
                    held.payload.assign((const uint8_t *)buf, (const uint8_t *)buf + len);
                    held.flags = flags;
                    held.hasDestAddr = (dest_addr != NULL && addrlen > 0);
                    if (held.hasDestAddr) {
                        memcpy(&held.destAddr, dest_addr, MIN(sizeof(held.destAddr), (size_t)addrlen));
                        held.addrLen = addrlen;
                    }
                    held.timestampMs = NowMilliseconds();
                    gHeldTXQueue.push_back(std::move(held));
                    aether_atomic_store(&gState->heldPacketsCount, (uint64_t)gHeldTXQueue.size());
                }
                pthread_mutex_unlock(&gQueueMutex);
                // Pretend send succeeded so the app/game engine does not disconnect
                return (ssize_t)len;
            } else if (mode == AetherModeDropPacket) {
                aether_atomic_fetch_add(&gState->droppedPacketsCount, 1);
                return (ssize_t)len;
            }
        }

        // Optional packet duplication (Settings Tab)
        uint32_t dupPct = aether_atomic_load(&gState->duplicatePacketPercent);
        if (dupPct > 0 && isUDP && arc4random_uniform(100) < dupPct) {
            orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        // Real-time TX detail logging (when not holding/dropping - those short-circuit above)
        if (mode != AetherModeHoldQueue && mode != AetherModeDropPacket) {
            char addrStr[INET6_ADDRSTRLEN] = {0};
            if (dest_addr && addrlen > 0 &&
                (dest_addr->sa_family == AF_INET || dest_addr->sa_family == AF_INET6)) {
                void *addrPtr = NULL;
                if (dest_addr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in *)dest_addr)->sin_addr;
                } else {
                    addrPtr = &((struct sockaddr_in6 *)dest_addr)->sin6_addr;
                }
                inet_ntop(dest_addr->sa_family, addrPtr, addrStr, sizeof(addrStr));
            }
            AetherLogDaemon(@"[TX %s %zuB -> %s] fd=%d",
                            isTCP ? "TCP" : "UDP", len, addrStr[0] ? addrStr : "?", sockfd);
        }
    }

    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t hooked_send(int sockfd, const void *buf, size_t len, int flags) {
    return hooked_sendto(sockfd, buf, len, flags, NULL, 0);
}

static ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    bool isTCP = false, isUDP = false;
    if (InspectSocketProtocol(sockfd, &isTCP, &isUDP) && gState) {
        size_t totalBytes = 0;
        if (msg) {
            for (int i = 0; i < msg->msg_iovlen; i++) {
                totalBytes += msg->msg_iov[i].iov_len;
            }
        }
        if (isTCP) aether_atomic_fetch_add(&gState->totalTCPPacketsTX, 1);
        if (isUDP) aether_atomic_fetch_add(&gState->totalUDPPacketsTX, 1);
        aether_atomic_fetch_add(&gState->totalBytesTX, totalBytes);

        uint8_t mode = aether_atomic_load(&gState->interceptMode);

        // Delay/Jitter network simulation applies to ALL matching packets
        if (mode == AetherModeDelayJitter && AetherDirectionProtoMatch(true, isTCP, isUDP)) {
            ApplyNetworkConditioningDelay(totalBytes);
            AetherLogDaemon(@"[TX %s %zuB] delay+jitter applied", isTCP ? "TCP" : "UDP", totalBytes);
        }

        uint32_t ratio = 0;
        if (ShouldInterceptPacket(true, isTCP, isUDP, &ratio)) {
            if (mode == AetherModeHoldQueue || mode == AetherModeDropPacket) {
                aether_atomic_fetch_add(&gState->droppedPacketsCount, 1);
                return (ssize_t)totalBytes;
            }
        }

        // Real-time TX detail logging (when not holding/dropping)
        if (mode != AetherModeHoldQueue && mode != AetherModeDropPacket) {
            AetherLogDaemon(@"[TX %s %zuB] sendmsg fd=%d", isTCP ? "TCP" : "UDP", totalBytes, sockfd);
        }
    }
    return orig_sendmsg(sockfd, msg, flags);
}

// ============================================================================
// Hooked Inbound (Download / RX) Socket Functions
// ============================================================================
static ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen) {
    bool isTCP = false, isUDP = false;
    bool isTrackedSocket = InspectSocketProtocol(sockfd, &isTCP, &isUDP);

    if (isTrackedSocket && gState) {
        uint8_t mode = aether_atomic_load(&gState->interceptMode);

        // Delay/Jitter network simulation applies to ALL matching packets
        if (mode == AetherModeDelayJitter && AetherDirectionProtoMatch(false, isTCP, isUDP)) {
            ApplyNetworkConditioningDelay(len);
        }

        uint32_t ratio = 0;
        if (ShouldInterceptPacket(false /* isUpload = false (Download) */, isTCP, isUDP, &ratio)) {
            if (mode == AetherModeHoldQueue) {
                // For non-blocking game/app sockets, return EWOULDBLOCK so inbound packets
                // stay queued inside the XNU kernel socket receive buffer (soi_rcv) until unpaused!
                aether_atomic_fetch_add(&gState->heldPacketsCount, 1);
                errno = EWOULDBLOCK;
                return -1;
            } else if (mode == AetherModeDropPacket) {
                // Consume and discard the inbound datagram
                ssize_t consumed = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
                if (consumed > 0) {
                    aether_atomic_fetch_add(&gState->droppedPacketsCount, 1);
                }
                errno = EWOULDBLOCK;
                return -1;
            }
        }
    }

    ssize_t bytesRead = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (bytesRead > 0 && isTrackedSocket && gState) {
        if (isTCP) aether_atomic_fetch_add(&gState->totalTCPPacketsRX, 1);
        if (isUDP) aether_atomic_fetch_add(&gState->totalUDPPacketsRX, 1);
        aether_atomic_fetch_add(&gState->totalBytesRX, (uint64_t)bytesRead);
        // Real-time packet detail logging
        AetherLogDaemon(@"[RX %s %zdB] bytes rx", isTCP ? "TCP" : "UDP", bytesRead);
    }
    return bytesRead;
}

static ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags) {
    return hooked_recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

static ssize_t hooked_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    bool isTCP = false, isUDP = false;
    bool isTrackedSocket = InspectSocketProtocol(sockfd, &isTCP, &isUDP);

    if (isTrackedSocket && gState) {
        uint8_t mode = aether_atomic_load(&gState->interceptMode);

        // Delay/Jitter network simulation applies to ALL matching packets
        if (mode == AetherModeDelayJitter && AetherDirectionProtoMatch(false, isTCP, isUDP)) {
            size_t len = 0;
            if (msg) {
                for (int i = 0; i < msg->msg_iovlen; i++) {
                    len += msg->msg_iov[i].iov_len;
                }
            }
            ApplyNetworkConditioningDelay(len);
        }

        uint32_t ratio = 0;
        if (ShouldInterceptPacket(false, isTCP, isUDP, &ratio)) {
            if (mode == AetherModeHoldQueue) {
                aether_atomic_fetch_add(&gState->heldPacketsCount, 1);
                errno = EWOULDBLOCK;
                return -1;
            } else if (mode == AetherModeDropPacket) {
                ssize_t consumed = orig_recvmsg(sockfd, msg, flags);
                if (consumed > 0) aether_atomic_fetch_add(&gState->droppedPacketsCount, 1);
                errno = EWOULDBLOCK;
                return -1;
            }
        }
    }

    ssize_t bytesRead = orig_recvmsg(sockfd, msg, flags);
    if (bytesRead > 0 && isTrackedSocket && gState) {
        if (isTCP) aether_atomic_fetch_add(&gState->totalTCPPacketsRX, 1);
        if (isUDP) aether_atomic_fetch_add(&gState->totalUDPPacketsRX, 1);
        aether_atomic_fetch_add(&gState->totalBytesRX, (uint64_t)bytesRead);
        AetherLogDaemon(@"[RX %s %zd B] recvmsg", isTCP ? "TCP" : "UDP", bytesRead);
    }
    return bytesRead;
}

// ============================================================================
// Constructor: Automatically invoked when libNetHookPayload.dylib is injected
// ============================================================================
__attribute__((constructor))
static void AetherPayloadInitializer(void) {
    gState = AetherGetSharedState();

    struct rebinding socketHooks[] = {
        { "send",     (void *)hooked_send,     (void **)&orig_send },
        { "sendto",   (void *)hooked_sendto,   (void **)&orig_sendto },
        { "sendmsg",  (void *)hooked_sendmsg,  (void **)&orig_sendmsg },
        { "recv",     (void *)hooked_recv,     (void **)&orig_recv },
        { "recvfrom", (void *)hooked_recvfrom, (void **)&orig_recvfrom },
        { "recvmsg",  (void *)hooked_recvmsg,  (void **)&orig_recvmsg },
    };
    rebind_symbols(socketHooks, sizeof(socketHooks) / sizeof(socketHooks[0]));

    // Only mark/announce when THIS process is (or becomes) the attached target.
    if (AetherHookGatesPass()) {
        if (gState) aether_atomic_store(&gState->isInjected, true);
        AetherLogDaemon(@"[pid %d] payload armed in target (bundle=%s)",
                        getpid(), gOwnBundleID.UTF8String ?: "?");
    }

    // Register Darwin Notification listener to flush held packets immediately on unpause
    int flushToken = 0;
    notify_register_dispatch(kAetherNotifyFlushQueue, &flushToken, dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^(int token) {
        FlushHeldPacketQueue();
    });

    // Log capture start/stop transitions (user-requested action logging).
    int stateLogToken = 0;
    notify_register_dispatch(kAetherNotifyStateChanged, &stateLogToken, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(int token) {
        AetherSharedState *st = AetherGetSharedState();
        if (!st) return;
        static BOOL lastArmed = NO;
        BOOL nowArmed = aether_atomic_load(&st->interceptionActive) && AetherHookGatesPass();
        if (nowArmed != lastArmed) {
            lastArmed = nowArmed;
            AetherLogDaemon(@"[pid %d] capture %s (mode=%u dir=%u proto=%u) (bundle=%s)",
                            getpid(), nowArmed ? "START" : "STOP",
                            aether_atomic_load(&st->interceptMode),
                            aether_atomic_load(&st->direction),
                            aether_atomic_load(&st->protocolFilter),
                            gOwnBundleID.UTF8String ?: "?");
        }
    });

    // Log configuration changes for real-time visibility in the log viewer
    int configLogToken = 0;
    notify_register_dispatch(kAetherNotifyConfigChanged, &configLogToken, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(int token) {
        if (gState && AetherHookGatesPass()) {
            AetherLogDaemon(@"[pid %d] config changed: mode=%u latency=%ums jitter=%ums bw=%ukbps",
                            getpid(),
                            aether_atomic_load(&gState->interceptMode),
                            aether_atomic_load(&gState->simulatedLatencyMs),
                            aether_atomic_load(&gState->simulatedJitterMs),
                            aether_atomic_load(&gState->bandwidthLimitKbps));
        }
    });
}
