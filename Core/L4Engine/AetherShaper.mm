//
//  AetherShaper.mm
//  AetherNet — enforcement lane (PF/dummynet + SIGSTOP) & root helper
//

#import <Foundation/Foundation.h>

#import "AetherShaper.h"
#import "../../Core/AetherLog.h"
#import "../../headers/AetherNetShared.h"
#import "../../headers/PrivateSystemSPI.h"

#include <errno.h>
#include <netinet/in.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char **environ;

#define AETHER_PF_CONF   "/var/mobile/Library/Caches/com.aethernet.pf.conf"
#define AETHER_PF_ANCHOR "com.apple/aethernet"

// ===========================================================================
// 0. Locating our own binary (the root helper is the same executable)
// ===========================================================================
static NSString *AetherOwnExecutablePath(void) {
    uint32_t size = 0;
    _NSGetExecutablePath(NULL, &size);
    if (size == 0) return nil;
    char *buf = (char *)calloc(1, (size_t)size + 1);
    if (!buf) return nil;
    if (_NSGetExecutablePath(buf, &size) != 0) { free(buf); return nil; }
    NSString *path = [NSString stringWithUTF8String:buf];
    free(buf);
    return path;
}

// ===========================================================================
// 1. Running a command as root (persona UID 0)
// ===========================================================================
// Both the short-lived verbs and the long-lived tap helper are the same
// binary, spawned with the persona UID 0 trick; only the "wait for it" part
// differs.
static int AetherSpawnRoot(NSArray<NSString *> *argv, pid_t *outPID) {
    NSString *exec = AetherOwnExecutablePath();
    if (!exec) return -1;

    const char **cargv = (const char **)calloc((size_t)argv.count + 2, sizeof(char *));
    cargv[0] = [exec fileSystemRepresentation];
    for (NSUInteger i = 0; i < argv.count; i++) {
        cargv[i + 1] = [argv[i] UTF8String];
    }
    cargv[argv.count + 1] = NULL;

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#if !TARGET_OS_SIMULATOR
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
#endif

    pid_t child = 0;
    int rc = posix_spawn(&child, [exec fileSystemRepresentation], NULL, &attr,
                         (char **)cargv, environ);
    posix_spawnattr_destroy(&attr);
    free((void *)cargv);
    if (rc != 0) return rc;
    if (outPID) *outPID = child;
    return 0;
}

int AetherSpawnRootChild(NSArray<NSString *> *argv, pid_t *outPID) {
    return AetherSpawnRoot(argv, outPID);
}

static int AetherRunAsRoot(NSArray<NSString *> *argv, NSString **outOutput) {
    if (!AetherOwnExecutablePath()) {
        if (outOutput) *outOutput = @"cannot locate own executable";
        return -1;
    }

    NSMutableArray *all = [NSMutableArray arrayWithObject:@"-rootctl"];
    [all addObjectsFromArray:argv];

    pid_t child = 0;
    int rc = AetherSpawnRoot(all, &child);
    if (rc != 0) {
        if (outOutput) *outOutput = [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(rc)];
        return -2;
    }

    int status = 0;
    waitpid(child, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -3;
    if (outOutput) *outOutput = [NSString stringWithFormat:@"exit=%d", code];
    return code;
}

int AetherRunAsRootVerb(NSArray<NSString *> *argv, NSString **outOutput) {
    if (!AetherOwnExecutablePath()) {
        if (outOutput) *outOutput = @"cannot locate own executable";
        return -2;
    }
    return AetherRunAsRoot(argv, outOutput);
}

// ===========================================================================
// 2. Capability probe
// ===========================================================================
static uint32_t gCachedCaps = 0;
static BOOL     gCapsProbed = NO;
// YES once "pf-apply" has really installed an anchor — drives the teardown.
static BOOL     gPFInstalled = NO;

static BOOL AetherFileExecutable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR);
}

uint32_t AetherShaperCapabilities(void) {
    if (gCapsProbed) return gCachedCaps;
    gCapsProbed = YES;

    uint32_t caps = 0;
    const char *pfctlPaths[] = { "/sbin/pfctl", "/usr/sbin/pfctl", "/usr/libexec/pfctl", NULL };
    const char *dnctlPaths[] = { "/sbin/dnctl", "/usr/sbin/dnctl", "/usr/bin/dnctl", NULL };

    for (int i = 0; pfctlPaths[i]; i++) {
        if (AetherFileExecutable(pfctlPaths[i])) { caps |= AETHER_SHAPER_CAP_PFCTL; break; }
    }
    for (int i = 0; dnctlPaths[i]; i++) {
        if (AetherFileExecutable(dnctlPaths[i])) { caps |= AETHER_SHAPER_CAP_DUMMYNET; break; }
    }

    // The freeze primitive only works if we can actually spawn a root helper.
    NSString *out = nil;
    int rc = AetherRunAsRoot(@[ @"probe" ], &out);
    if (rc == 0) {
        caps |= AETHER_SHAPER_CAP_FREEZE;
    } else {
        AetherLogDaemon(@"[shaper] root helper probe failed: %@", out ?: @"?");
    }

    gCachedCaps = caps;
    AetherLogDaemon(@"[shaper] capabilities pfctl=%d dnctl=%d freeze=%d",
                    (caps & AETHER_SHAPER_CAP_PFCTL) ? 1 : 0,
                    (caps & AETHER_SHAPER_CAP_DUMMYNET) ? 1 : 0,
                    (caps & AETHER_SHAPER_CAP_FREEZE) ? 1 : 0);
    return caps;
}

// ===========================================================================
// 3. Rule generation
// ===========================================================================
static NSString *AetherBuildPFConf(pid_t pid, AetherSharedState *st, NSString **note) {
    NSMutableString *conf = [NSMutableString string];
    [conf appendString:@"# AetherNet — generated, do not edit\n"];

    AetherInterceptMode mode = (AetherInterceptMode)aether_atomic_load(&st->interceptMode);
    uint32_t ratio = aether_atomic_load(&st->captureRatioPercent);
    uint32_t rxRatio = aether_atomic_load(&st->downloadHoldPercent);
    uint32_t txRatio = aether_atomic_load(&st->uploadHoldPercent);
    uint32_t delayMs = aether_atomic_load(&st->simulatedLatencyMs);
    uint32_t bwKbps = aether_atomic_load(&st->bandwidthLimitKbps);
    AetherTrafficDirection dir = (AetherTrafficDirection)aether_atomic_load(&st->direction);
    AetherProtocolFilter proto = (AetherProtocolFilter)aether_atomic_load(&st->protocolFilter);

    NSString *protoStr = (proto == AetherProtoUDPOnly) ? @"udp" :
                         (proto == AetherProtoTCPOnly) ? @"tcp" : @"{ tcp, udp }";

    if (mode == AetherModeDropPacket) {
        for (uint32_t i = 0; i < st->socketEntryCount; i++) {
            AetherSocketEntry e = st->activeSockets[i];
            if (e.localPort == 0) continue;
            if (e.protocol == IPPROTO_UDP && proto == AetherProtoTCPOnly) continue;
            if (e.protocol == IPPROTO_TCP && proto == AetherProtoUDPOnly) continue;

            uint32_t inRatio  = (rxRatio * ratio) / 100u;
            uint32_t outRatio = (txRatio * ratio) / 100u;

            if (dir == AetherDirectionBoth || dir == AetherDirectionDownload) {
                [conf appendFormat:@"block drop in quick proto %@ from any to any port %u probability %u\n",
                 protoStr, e.localPort, MIN(inRatio, 99u)];
            }
            if (dir == AetherDirectionBoth || dir == AetherDirectionUpload) {
                [conf appendFormat:@"block drop out quick proto %@ from any port %u to any probability %u\n",
                 protoStr, e.localPort, MIN(outRatio, 99u)];
            }
        }
        if (note) *note = @"pf:block-drop";
        return conf;
    }

    if (mode == AetherModeDelayJitter) {
        // dummynet pipes carry the delay/bandwidth/loss; PF only has to push
        // the target's packets through them.
        for (uint32_t i = 0; i < st->socketEntryCount; i++) {
            AetherSocketEntry e = st->activeSockets[i];
            if (e.localPort == 0) continue;
            if (e.protocol == IPPROTO_UDP && proto == AetherProtoTCPOnly) continue;
            if (e.protocol == IPPROTO_TCP && proto == AetherProtoUDPOnly) continue;

            if (dir == AetherDirectionBoth || dir == AetherDirectionDownload) {
                [conf appendFormat:@"dummynet in quick proto %@ from any to any port %u pipe 1\n",
                 protoStr, e.localPort];
            }
            if (dir == AetherDirectionBoth || dir == AetherDirectionUpload) {
                [conf appendFormat:@"dummynet out quick proto %@ from any port %u to any pipe 1\n",
                 protoStr, e.localPort];
            }
        }
        if (note) *note = [NSString stringWithFormat:@"dummynet:delay=%ums bw=%ukbps", delayMs, bwKbps];
        return conf;
    }

    if (mode == AetherModeHoldQueue) {
        // NOTE: see AetherShaperApply — the only primitive iOS leaves us for
        // "hold" without in-process hooks is SIGSTOP, and a stopped process
        // sends nothing at all.  The capture will legitimately show zero
        // packets while this mode is active.
        // Without in-process hooks "holding" a packet is not observable by the
        // target: the kernel already delivered it.  The faithful equivalent is
        // to stop the process from draining its sockets (see Freeze below).
        if (note) *note = @"freeze:hold";
        return nil;
    }

    if (note) *note = @"unsupported-without-injection";
    return nil;
}

// ===========================================================================
// 4. Public API
// ===========================================================================
int AetherShaperApply(pid_t pid, char *errBuf, size_t errBufLen) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st || pid <= 0) {
        snprintf(errBuf, errBufLen, "no target");
        return -1;
    }

    uint32_t caps = AetherShaperCapabilities();
    NSString *note = nil;
    NSString *conf = AetherBuildPFConf(pid, st, &note);
    NSString *output = nil;
    int rc = 0;

    AetherInterceptMode mode = (AetherInterceptMode)aether_atomic_load(&st->interceptMode);

    // Observe: the user asked for visibility, not interference.  Freezing the
    // target here (the only primitive iOS leaves us) would defeat the purpose —
    // a stopped process sends nothing to observe.
    if (mode == AetherModeObserve) {
        AetherLogDaemon(@"[shaper] observe mode — target left running, traffic untouched");
        return 0;
    }

    if (conf.length > 0 && (caps & AETHER_SHAPER_CAP_PFCTL)) {
        NSError *werr = nil;
        BOOL written = [conf writeToFile:@AETHER_PF_CONF
                              atomically:YES
                                encoding:NSUTF8StringEncoding
                                   error:&werr];
        if (!written) {
            snprintf(errBuf, errBufLen, "cannot write %s: %s", AETHER_PF_CONF,
                     [[werr localizedDescription] UTF8String] ?: "?");
            return -2;
        }
        chmod(AETHER_PF_CONF, 0644);

        if (mode == AetherModeDelayJitter && (caps & AETHER_SHAPER_CAP_DUMMYNET)) {
            uint32_t delayMs = aether_atomic_load(&st->simulatedLatencyMs);
            uint32_t bwKbps  = aether_atomic_load(&st->bandwidthLimitKbps);
            uint32_t jitter  = aether_atomic_load(&st->simulatedJitterMs);
            NSString *bwArg = bwKbps > 0
                ? [NSString stringWithFormat:@"%uKbit/s", bwKbps]
                : @"0";
            rc = AetherRunAsRoot(@[ @"dn-apply",
                                    [NSString stringWithFormat:@"%u", delayMs + (jitter / 2)],
                                    bwArg ], &output);
            if (rc != 0) {
                AetherLogDaemon(@"[shaper] dnctl failed (%@) — falling back to freeze", output);
            }
        }

        rc = AetherRunAsRoot(@[ @"pf-apply", @AETHER_PF_CONF ], &output);
        if (rc != 0) {
            snprintf(errBuf, errBufLen, "pf-apply failed (%s)", [output UTF8String] ?: "?");
            return -3;
        }
        AetherLogDaemon(@"[shaper] PF rules installed (%@) for pid %d: %@",
                        note ?: @"?", pid, output ?: @"");
        gPFInstalled = YES;
    }

    // iOS ships neither pfctl nor dnctl, so any rule set we built is dead
    // weight: say so instead of reporting success while nothing is enforced.
    if (conf.length > 0 && !(caps & AETHER_SHAPER_CAP_PFCTL)) {
        AetherLogDaemon(@"[shaper] rules were built but pfctl is not installed on this "
                        @"device — no kernel shaping without in-process hooks");
        rc = -6;
    }

    // Hold (and Drop) fall back to the freeze primitive: stopping the process
    // is the only faithful "nothing gets through" we can do with no kernel
    // patch and no injection.  Delay and Tamper have no such equivalent.
    if (mode == AetherModeHoldQueue || rc != 0 || conf.length == 0) {
        bool freezeIsEquivalent = (mode == AetherModeHoldQueue ||
                                   mode == AetherModeDropPacket);
        bool freezeAllowed = aether_atomic_load(&st->allowFreeze) != 0;

        // 4.1.3 — SIGSTOP means a FROZEN APP: no rendering, no FPS, and nothing
        // left for the tap to capture.  Hold/Drop reach it implicitly on every
        // device without pfctl/dnctl and without injection, so it used to fire
        // the moment the user flipped the toggle.  It is now opt-in: without
        // an explicit YES we simply enforce nothing and keep capturing.
        if (freezeIsEquivalent && !freezeAllowed) {
            snprintf(errBuf, errBufLen,
                     "mode %u can only be enforced by SIGSTOP here (pfctl/dnctl absent, "
                     "injection unavailable) - freeze is OFF, so the target keeps "
                     "running and the BPF tap keeps capturing",
                     (unsigned)mode);
            AetherLogDaemon(@"[shaper] %s — turn on 'Freeze target (SIGSTOP)' in "
                            @"Settings only if you really want to stop the app", errBuf);
            return -7;
        }
        if (freezeIsEquivalent && (caps & AETHER_SHAPER_CAP_FREEZE)) {
            int frc = AetherShaperFreeze(pid, YES, errBuf, errBufLen);
            if (frc != 0) return frc;
            return 0;
        }
        if (!freezeIsEquivalent) {
            snprintf(errBuf, errBufLen,
                     "mode %u needs PF/dummynet or in-process hooks - neither is "
                     "available here (pfctl=%u dnctl=%u, injected=0)",
                     (unsigned)mode,
                     (caps & AETHER_SHAPER_CAP_PFCTL) ? 1u : 0u,
                     (caps & AETHER_SHAPER_CAP_DUMMYNET) ? 1u : 0u);
            return -5;
        }
        snprintf(errBuf, errBufLen, "no enforcement primitive available");
        return -4;
    }

    return 0;
}

int AetherShaperFlush(char *errBuf, size_t errBufLen) {
    AetherSharedState *st = AetherGetSharedState();
    NSString *output = nil;
    int rc = 0;
    // Only tear down PF when we actually installed rules: on iOS there is no
    // pfctl at all, and calling it on every stop just floods the log with
    // "pf-flush failed (exit=6)".
    if (gPFInstalled && (AetherShaperCapabilities() & AETHER_SHAPER_CAP_PFCTL)) {
        rc = AetherRunAsRoot(@[ @"pf-flush" ], &output);
        gPFInstalled = NO;
        if (rc != 0) {
            AetherLogDaemon(@"[shaper] pf-flush failed: %@", output ?: @"?");
        }
    }

    pid_t frozen = st ? (pid_t)aether_atomic_load(&st->rootFrozenPid) : 0;
    if (frozen > 0) {
        AetherShaperFreeze(frozen, NO, errBuf, errBufLen);
    }
    if (rc != 0) {
        snprintf(errBuf, errBufLen, "pf-flush failed (%s)", [output UTF8String] ?: "?");
    }
    return rc;
}

int AetherShaperFreeze(pid_t pid, bool freeze, char *errBuf, size_t errBufLen) {
    if (pid <= 0) {
        snprintf(errBuf, errBufLen, "invalid pid");
        return -1;
    }
    NSString *output = nil;
    int rc = AetherRunAsRoot(@[ freeze ? @"freeze" : @"thaw",
                                [NSString stringWithFormat:@"%d", pid] ], &output);
    if (rc != 0) {
        snprintf(errBuf, errBufLen, "%s failed (%s)", freeze ? "freeze" : "thaw",
                 [output UTF8String] ?: "?");
        return -2;
    }
    AetherLogDaemon(@"[shaper] pid %d %@", pid, freeze ? @"SIGSTOP" : @"SIGCONT");
    if (freeze) {
        // Loud on purpose: every "matched=0" report so far has come from a
        // session where the target was stopped by us.  A SIGSTOPped process has
        // no traffic to capture, so the tap is working correctly and empty.
        AetherLogDaemon(@"[shaper] WARNING: pid %d is now FROZEN (SIGSTOP) — it cannot send or "
                        @"receive anything, so the capture will show 0 packets until you switch "
                        @"to Observe mode. This mode is enforcement, not capture.", pid);
        AetherSharedState *stW = AetherGetSharedState();
        if (stW) {
            strncpy(stW->engineStatus,
                    "Hold mode: target FROZEN (SIGSTOP) - no traffic to capture",
                    sizeof(stW->engineStatus) - 1);
            stW->engineStatus[sizeof(stW->engineStatus) - 1] = '\0';
        }
    }
    return 0;
}

// ===========================================================================
// 5. -rootctl: what actually runs as uid 0
// ===========================================================================
static int AetherRunCommand(const char *path, NSArray<NSString *> *args) {
    const char **cargv = (const char **)calloc((size_t)args.count + 2, sizeof(char *));
    cargv[0] = path;
    for (NSUInteger i = 0; i < args.count; i++) cargv[i + 1] = [args[i] UTF8String];
    cargv[args.count + 1] = NULL;

    pid_t child = 0;
    int rc = posix_spawn(&child, path, NULL, NULL, (char **)cargv, environ);
    free((void *)cargv);
    if (rc != 0) return -1;
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static NSString *AetherFirstExecutable(NSArray<NSString *> *candidates) {
    for (NSString *p in candidates) {
        if (AetherFileExecutable([p fileSystemRepresentation])) return p;
    }
    return nil;
}

// ===========================================================================
// 4b. Ping simulation (lag switch)
// ---------------------------------------------------------------------------
// iOS ships neither pfctl nor dnctl, and on a device where task_for_pid fails
// there is no in-process hook either, so there is no queue anywhere that could
// hold a packet for N milliseconds.  The one primitive that always exists is
// SIGSTOP: while the target is stopped its sockets stop draining, anything it
// would have sent sits still, and the far end sees a stall.  Repeating that on
// a duty cycle is exactly what a hardware "lag switch" does, and it is the only
// way to move a game's ping here.
//
// lagSpikeMs == 0 => the worker stays alive but never signals the target, so
// moving the slider takes effect without restarting the lanes.
// ===========================================================================
static pthread_t              gLagThread;
static pid_t                  gLagPID = 0;
static _Atomic(int)           gLagRunning = 0;
static _Atomic(uint32_t)      gLagSpikes = 0;

// The daemon and the target are both uid 501, so kill() works directly and
// costs nothing; the root helper is only a fallback.  Two spawned helpers per
// cycle would otherwise dominate the CPU at a 100 ms period.
static bool AetherLagStall(pid_t pid, bool stop, char *errBuf, size_t errBufLen) {
    if (kill(pid, stop ? SIGSTOP : SIGCONT) == 0) {
        AetherSharedState *st = AetherGetSharedState();
        if (st) aether_atomic_store(&st->freezeActive, (uint8_t)(stop ? 1 : 0));
        return true;
    }
    if (errno == ESRCH) return false;                 // target is gone
    return AetherShaperFreeze(pid, stop, errBuf, errBufLen) == 0;
}

static void AetherLagSleep(uint32_t ms) {
    // Chunked so a stop request is honoured within ~20 ms.
    while (ms > 0 && aether_atomic_load(&gLagRunning)) {
        uint32_t chunk = ms > 20 ? 20 : ms;
        usleep((useconds_t)chunk * 1000);
        ms -= chunk;
    }
}

static void *AetherLagThreadMain(void *arg) {
    (void)arg;
    char errBuf[160];
    pid_t pid = gLagPID;
    uint32_t sinceReport = 0;
    uint32_t spikesAtReport = 0;

    while (aether_atomic_load(&gLagRunning)) {
        AetherSharedState *st = AetherGetSharedState();
        uint32_t spike = st ? aether_atomic_load(&st->lagSpikeMs) : 0u;
        uint32_t cycle = st ? aether_atomic_load(&st->lagCycleMs) : 0u;
        if (spike == 0u) { usleep(100000); continue; }     // OFF: never signal
        if (cycle < spike + 20u) cycle = spike + 20u;

        if (!AetherLagStall(pid, true, errBuf, sizeof(errBuf))) break;
        AetherLagSleep(spike);
        // ALWAYS thaw — leaving the target stopped would be a frozen app.
        AetherLagStall(pid, false, errBuf, sizeof(errBuf));
        aether_atomic_fetch_add(&gLagSpikes, 1u);
        AetherLagSleep(cycle - spike);

        sinceReport += cycle;
        if (sinceReport >= 5000u) {
            uint32_t now = aether_atomic_load(&gLagSpikes);
            AetherLogDaemon(@"[lag] %u stall(s) of %u ms in the last %.1f s (duty %u%%)",
                            now - spikesAtReport, spike, sinceReport / 1000.0,
                            (unsigned)((spike * 100u) / cycle));
            sinceReport = 0;
            spikesAtReport = now;
        }
    }

    // Final safety net: never leave the target SIGSTOPped.
    AetherLagStall(pid, false, errBuf, sizeof(errBuf));
    aether_atomic_store(&gLagRunning, 0);
    AetherLogDaemon(@"[lag] worker exited — pid %d resumed", pid);
    return NULL;
}

int AetherLagSwitchStart(pid_t pid, char *errBuf, size_t errBufLen) {
    if (pid <= 0) { snprintf(errBuf, errBufLen, "invalid pid"); return -1; }
    if (aether_atomic_load(&gLagRunning)) {
        gLagPID = pid;                       // target changed; keep the worker
        return 0;
    }
    if (!(AetherShaperCapabilities() & AETHER_SHAPER_CAP_FREEZE)) {
        snprintf(errBuf, errBufLen, "no freeze primitive on this device");
        return -3;
    }

    AetherSharedState *st = AetherGetSharedState();
    uint32_t spike = st ? aether_atomic_load(&st->lagSpikeMs) : 0u;
    uint32_t cycle = st ? aether_atomic_load(&st->lagCycleMs) : 0u;

    gLagPID = pid;
    aether_atomic_store(&gLagSpikes, 0u);
    aether_atomic_store(&gLagRunning, 1);
    int rc = pthread_create(&gLagThread, NULL, AetherLagThreadMain, NULL);
    if (rc != 0) {
        aether_atomic_store(&gLagRunning, 0);
        snprintf(errBuf, errBufLen, "pthread_create failed (%s)", strerror(rc));
        return -4;
    }
    pthread_detach(gLagThread);
    if (spike == 0u) {
        AetherLogDaemon(@"[lag] worker idle — ping simulation is OFF (spike = 0 ms)");
    } else {
        AetherLogDaemon(@"[lag] ping simulation armed: %u ms stall every %u ms on pid %d "
                        @"(duty %u%%) — the app will visibly stutter, that is the mechanism",
                        spike, cycle, pid, (unsigned)((spike * 100u) / (cycle ? cycle : 1u)));
    }
    return 0;
}

void AetherLagSwitchStop(void) {
    if (!aether_atomic_load(&gLagRunning)) return;
    aether_atomic_store(&gLagRunning, 0);
    // The worker thaws the target on its way out; give it a moment, then make
    // sure with an explicit SIGCONT so a stopped app can never be left behind.
    usleep(150000);
    char errBuf[160] = {0};
    if (gLagPID > 0) AetherLagStall(gLagPID, false, errBuf, sizeof(errBuf));
    gLagPID = 0;
    AetherLogDaemon(@"[lag] ping simulation off — target resumed");
}

bool AetherLagSwitchIsRunning(void) {
    return aether_atomic_load(&gLagRunning) != 0;
}

int AetherRootCtlMain(int argc, char *argv[]) {
    @autoreleasepool {
        // Accept both calling conventions: main.mm hands us (argc-1, argv+1)
        // so that argv[1] is the verb, but a caller that forgets to strip the
        // "-rootctl" selector must not silently run the wrong verb (4.0.0 did
        // exactly that: every helper invocation died on "unknown verb:
        // -rootctl", which is why pfctl/dnctl/freeze were all reported
        // unavailable).
        if (argc >= 2 && strcmp(argv[1], "-rootctl") == 0) {
            argc -= 1;
            argv += 1;
        }
        if (argc < 2) return 2;
        NSString *verb = [NSString stringWithUTF8String:argv[1]];

        // --- probe: "can you really run as root?" --------------------------------
        if ([verb isEqualToString:@"probe"]) {
            uid_t euid = geteuid();
            AetherLogDaemonSync(@"[rootctl] probe: euid=%u uid=%u pid=%d",
                                (unsigned)euid, (unsigned)getuid(), (int)getpid());
            return (euid == 0) ? 0 : 1;
        }

        if (geteuid() != 0) {
            AetherLogDaemonSync(@"[rootctl] %@ attempted without root (euid=%u)",
                                verb, (unsigned)geteuid());
            return 77;
        }

        // --- freeze / thaw --------------------------------------------------------
        if (([verb isEqualToString:@"freeze"] || [verb isEqualToString:@"thaw"]) && argc >= 3) {
            pid_t pid = (pid_t)atoi(argv[2]);
            AetherSharedState *st = AetherGetSharedState();
            int sig = [verb isEqualToString:@"freeze"] ? SIGSTOP : SIGCONT;
            int rc = kill(pid, sig);
            if (rc != 0) {
                AetherLogDaemonSync(@"[rootctl] kill(%d, %d) failed: %s",
                                    pid, sig, strerror(errno));
                return 3;
            }
            if (st) {
                aether_atomic_store(&st->rootFrozenPid,
                                    [verb isEqualToString:@"freeze"] ? (int32_t)pid : 0);
                aether_atomic_store(&st->freezeActive,
                                    (uint8_t)([verb isEqualToString:@"freeze"] ? 1 : 0));
            }
            AetherLogDaemonSync(@"[rootctl] pid %d signal %d ok", pid, sig);
            return 0;
        }

        // --- kill <pid> [signal] ---------------------------------------------------
        // The UI app (uid 501) may not signal the root tap helper it spawned —
        // kill() to a uid-0 process returns EPERM — so it asks us instead.
        if ([verb isEqualToString:@"kill"] && argc >= 3) {
            pid_t victim = (pid_t)atoi(argv[2]);
            int   sig    = (argc >= 4) ? atoi(argv[3]) : SIGTERM;
            if (victim <= 0) return 3;
            if (kill(victim, sig) != 0) {
                AetherLogDaemonSync(@"[rootctl] kill(%d, %d) failed: %s",
                                    victim, sig, strerror(errno));
                return 3;
            }
            // Give it a moment to exit, then make sure.
            for (int i = 0; i < 10; i++) {
                usleep(30000);
                if (kill(victim, 0) != 0 && errno != EPERM) break;
            }
            if (kill(victim, 0) == 0 || errno == EPERM) {
                kill(victim, SIGKILL);
            }
            AetherLogDaemonSync(@"[rootctl] kill(%d, %d) ok", victim, sig);
            return 0;
        }

        // --- pf-apply -------------------------------------------------------------
        if ([verb isEqualToString:@"pf-apply"] && argc >= 3) {
            NSString *pfctl = AetherFirstExecutable(@[ @"/sbin/pfctl", @"/usr/sbin/pfctl",
                                                       @"/usr/libexec/pfctl" ]);
            if (!pfctl) { AetherLogDaemonSync(@"[rootctl] pfctl not found"); return 4; }

            // -E enables PF with a reference count, so we never disable a PF
            // that Apple's own clients are still using; -X would drop it.
            int rc = AetherRunCommand([pfctl fileSystemRepresentation], @[ @"-E" ]);
            if (rc != 0) {
                AetherLogDaemonSync(@"[rootctl] pfctl -E failed (%d)", rc);
            }
            rc = AetherRunCommand([pfctl fileSystemRepresentation],
                                  @[ @"-a", @AETHER_PF_ANCHOR, @"-f",
                                     [NSString stringWithUTF8String:argv[2]] ]);
            if (rc != 0) {
                AetherLogDaemonSync(@"[rootctl] pfctl -a %s -f %s failed (%d)",
                                    AETHER_PF_ANCHOR, argv[2], rc);
                return 5;
            }
            AetherLogDaemonSync(@"[rootctl] pf rules applied from %s", argv[2]);
            return 0;
        }

        // --- pf-flush -------------------------------------------------------------
        if ([verb isEqualToString:@"pf-flush"]) {
            NSString *pfctl = AetherFirstExecutable(@[ @"/sbin/pfctl", @"/usr/sbin/pfctl",
                                                       @"/usr/libexec/pfctl" ]);
            if (!pfctl) return 4;
            int rc = AetherRunCommand([pfctl fileSystemRepresentation],
                                      @[ @"-a", @AETHER_PF_ANCHOR, @"-F", @"all" ]);
            AetherLogDaemonSync(@"[rootctl] pf rules flushed (%d)", rc);
            return rc == 0 ? 0 : 6;
        }

        // --- dn-apply <delayMs> <bw e.g. "128Kbit/s"> --------------------------------
        if ([verb isEqualToString:@"dn-apply"] && argc >= 4) {
            NSString *dnctl = AetherFirstExecutable(@[ @"/sbin/dnctl", @"/usr/sbin/dnctl",
                                                       @"/usr/bin/dnctl" ]);
            if (!dnctl) { AetherLogDaemonSync(@"[rootctl] dnctl not found"); return 7; }
            NSString *delay = [NSString stringWithUTF8String:argv[2]];
            NSString *bw    = [NSString stringWithUTF8String:argv[3]];
            NSMutableArray *args = [NSMutableArray arrayWithArray:@[ @"pipe", @"1", @"config" ]];
            [args addObject:@"delay"];
            [args addObject:delay];
            if (![bw isEqualToString:@"0"]) {
                [args addObject:@"bw"];
                [args addObject:bw];
            }
            int rc = AetherRunCommand([dnctl fileSystemRepresentation], args);
            AetherLogDaemonSync(@"[rootctl] dnctl %@ -> %d", args, rc);
            return rc == 0 ? 0 : 8;
        }

        AetherLogDaemonSync(@"[rootctl] unknown verb: %@", verb);
        return 2;
    }
}
