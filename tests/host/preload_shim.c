//
//  preload_shim.c
//  AetherNet — LD_PRELOAD stand-in for the injected payload (host tests)
//
//  On iOS the hooks are installed by fishhook (Mach-O lazy pointer rewriting);
//  on Linux an LD_PRELOAD interposer does the same job.  Everything below the
//  interposition is the *shipped* code: AetherHookCoreSend/Recv from
//  Payload/AetherHookCore.c, driven by the shared state in
//  AetherNetShared.h exactly like the real payload.
//
//  SIGUSR2 plays the role of the Darwin "flush queue" notification.
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../Payload/AetherHookCore.h"
#include "host_support.h"

static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;

static bool AetherShimTargetGate(void) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return false;
    pid_t target = aether_atomic_load(&st->targetPID);
    return (target > 0 && (pid_t)target == getpid());
}

// The handler only raises a flag: doing the queue surgery inside a signal
// handler would risk re-entering the hold-queue mutex from the very thread
// that is holding it.
static volatile sig_atomic_t gFlushRequested = 0;

static void AetherShimEmit(void *ctx, const AetherHeldPacket *pkt) {
    (void)ctx;
    if (!pkt) return;
    if (pkt->hasAddr && real_sendto) {
        real_sendto(pkt->fd, pkt->payload, pkt->len, pkt->flags,
                    (const struct sockaddr *)pkt->addr, pkt->addrLen);
    } else if (real_send) {
        real_send(pkt->fd, pkt->payload, pkt->len, pkt->flags);
    }
}

static void AetherShimFlushHandler(int sig) {
    (void)sig;
    gFlushRequested = 1;
}

static void AetherShimServiceFlush(void) {
    if (!gFlushRequested) return;
    gFlushRequested = 0;
    AetherHookCoreFlushWith(NULL, AetherShimEmit);
    AetherHookCoreReleaseRX(1500);
}

static void AetherShimResolve(void) {
    real_send     = dlsym(RTLD_NEXT, "send");
    real_sendto   = dlsym(RTLD_NEXT, "sendto");
    real_recv     = dlsym(RTLD_NEXT, "recv");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_read     = dlsym(RTLD_NEXT, "read");
    real_write    = dlsym(RTLD_NEXT, "write");
}

__attribute__((constructor))
static void AetherShimInit(void) {
    AetherShimResolve();
    AetherHookCoreInit();
    AetherHookCoreSetLog(AetherHostLogLine);
    AetherHookCoreSetTargetGate(AetherShimTargetGate);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = AetherShimFlushHandler;
    sigaction(SIGUSR2, &sa, NULL);

    if (getenv("AETHER_TEST_DETERMINISTIC")) {
        AetherHookCoreSetDeterministic(true);
    }
    AetherHookCoreStartAutoFlushWatchdog(AetherShimEmit, NULL);
}

// --- interposed syscalls -----------------------------------------------------
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dst, socklen_t dstLen) {
    if (!real_sendto) AetherShimResolve();
    AetherShimServiceFlush();
    return AetherHookCoreSend(fd, buf, len, flags, dst, dstLen,
                              real_sendto, real_send);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    if (!real_send) AetherShimResolve();
    AetherShimServiceFlush();
    return AetherHookCoreSend(fd, buf, len, flags, NULL, 0, real_sendto, real_send);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src, socklen_t *srcLen) {
    if (!real_recvfrom) AetherShimResolve();
    AetherShimServiceFlush();
    return AetherHookCoreRecv(fd, buf, len, flags, src, srcLen, real_recvfrom);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    if (!real_recv) AetherShimResolve();
    AetherShimServiceFlush();
    return AetherHookCoreRecv(fd, buf, len, flags, NULL, NULL, real_recvfrom);
}

ssize_t write(int fd, const void *buf, size_t len) {
    if (!real_write) AetherShimResolve();
    bool isTCP = false, isUDP = false;
    if (AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) {
        return AetherHookCoreSend(fd, buf, len, 0, NULL, 0, real_sendto, real_send);
    }
    return real_write(fd, buf, len);
}

ssize_t read(int fd, void *buf, size_t len) {
    if (!real_read) AetherShimResolve();
    bool isTCP = false, isUDP = false;
    if (AetherHookCoreSocketIsIP(fd, &isTCP, &isUDP)) {
        return AetherHookCoreRecv(fd, buf, len, 0, NULL, NULL, real_recvfrom);
    }
    return real_read(fd, buf, len);
}
