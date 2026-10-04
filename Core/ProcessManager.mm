//
//  ProcessManager.mm
//  AetherNet — Process Enumeration, XNU Socket Telemetry & HUD Spawner
//
//  Path-aware capture architecture (see README §2 for the research behind it):
//    P1  BSD socket syscall lane      — injected dylib, fishhook on send/recv/…
//    P2  libnetwork lane              — injected dylib, fishhook on nw_connection_*
//    P3  kernel tap lane              — /dev/bpf, no injection, sees P1 *and* P2
//    P4  enforcement lane             — PF/dummynet + SIGSTOP freeze (root helper)
//
//  P1+P2 need a successful dylib injection (impossible on most plain
//  TrollStore devices: the target would have to accept unsigned code).
//  P3+P4 only need root + no-sandbox, so they are the guaranteed baseline.
//

#import "ProcessManager.h"
#import "AetherLog.h"
#import "../headers/PrivateSystemSPI.h"
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <spawn.h>
#include <notify.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <signal.h>
#include <netinet/in.h>

extern "C" char **environ;
extern "C" int AetherInjectDylibIntoPID(pid_t pid, const char *dylibPath, char *errBuf, size_t errBufLen);
extern "C" int AetherInjectAndArm(pid_t pid, const char *dylibPath, char *errBuf, size_t errBufLen);

#import "L4Engine/AetherKernelLane.h"
#import "L4Engine/AetherShaper.h"

@implementation AetherProcessInfo
@end

@interface AetherProcessManager ()
- (void)writeEngineStatus:(NSString *)text;
@end

@implementation AetherProcessManager {
    NSMutableDictionary<NSString *, LSApplicationProxy *> *_pathToAppProxyCache;
    NSTimer *_telemetryTimer;
}

+ (instancetype)sharedManager {
    static AetherProcessManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AetherProcessManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        _pathToAppProxyCache = [NSMutableDictionary dictionary];
        [self rebuildInstalledAppCache];
    }
    return self;
}

- (void)rebuildInstalledAppCache {
    [_pathToAppProxyCache removeAllObjects];
    Class wsClass = objc_getClass("LSApplicationWorkspace");
    if (!wsClass) return;

    LSApplicationWorkspace *workspace = [wsClass defaultWorkspace];
    NSArray<LSApplicationProxy *> *apps = [workspace allInstalledApplications];
    for (LSApplicationProxy *proxy in apps) {
        NSString *bundlePath = proxy.bundleURL.path;
        if (bundlePath.length > 0) {
            _pathToAppProxyCache[bundlePath] = proxy;
        }
    }
}

- (NSArray<AetherProcessInfo *> *)enumerateRunningProcessesWithFilter:(nullable NSString *)searchQuery
                                                         onlyUserApps:(BOOL)onlyUserApps {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t bufSize = 0;

    if (sysctl(mib, 4, NULL, &bufSize, NULL, 0) < 0 || bufSize == 0) {
        return @[];
    }

    bufSize += sizeof(struct kinfo_proc) * 32;
    struct kinfo_proc *procs = (struct kinfo_proc *)calloc(1, bufSize);
    if (!procs) return @[];

    if (sysctl(mib, 4, procs, &bufSize, NULL, 0) < 0) {
        free(procs);
        return @[];
    }

    size_t count = bufSize / sizeof(struct kinfo_proc);
    NSMutableArray<AetherProcessInfo *> *result = [NSMutableArray arrayWithCapacity:count];
    pid_t selfPID = getpid();

    for (size_t i = 0; i < count; i++) {
        struct kinfo_proc *kp = &procs[i];
        pid_t pid = kp->kp_proc.p_pid;
        if (pid <= 1 || pid == selfPID) continue;

        char pathBuf[PATH_MAX] = {0};
        proc_pidpath(pid, pathBuf, sizeof(pathBuf));
        NSString *execPath = pathBuf[0] ? [NSString stringWithUTF8String:pathBuf] : @"";
        NSString *commName = [NSString stringWithUTF8String:kp->kp_proc.p_comm];
        if (execPath.length > 0) {
            commName = [execPath lastPathComponent];
        }

        BOOL isAppBundle = [execPath containsString:@".app/"];
        BOOL isUserApp = [execPath hasPrefix:@"/var/containers/Bundle/Application/"] ||
                         [execPath hasPrefix:@"/private/var/containers/Bundle/Application/"];

        if (onlyUserApps && !isAppBundle) {
            continue;
        }

        AetherProcessInfo *info = [[AetherProcessInfo alloc] init];
        info.pid = pid;
        info.ppid = kp->kp_eproc.e_ppid;
        info.uid = kp->kp_eproc.e_ucred.cr_uid;
        info.processName = commName ?: @"unknown";
        info.displayName = info.processName;
        info.executablePath = execPath;
        info.isUserApp = isUserApp;
        info.bundleIdentifier = isUserApp ? @"com.user.application" : @"com.apple.system";

        // Match .app bundle path to LSApplicationProxy metadata + icon
        if (isAppBundle) {
            NSRange appRange = [execPath rangeOfString:@".app/"];
            if (appRange.location != NSNotFound) {
                NSString *bundleDir = [execPath substringToIndex:appRange.location + 4];
                LSApplicationProxy *proxy = _pathToAppProxyCache[bundleDir];
                if (proxy) {
                    if (proxy.localizedName.length > 0) info.displayName = proxy.localizedName;
                    if (proxy.applicationIdentifier.length > 0) info.bundleIdentifier = proxy.applicationIdentifier;
                } else {
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:
                        [bundleDir stringByAppendingPathComponent:@"Info.plist"]];
                    if (infoPlist[@"CFBundleDisplayName"]) {
                        info.displayName = infoPlist[@"CFBundleDisplayName"];
                    } else if (infoPlist[@"CFBundleName"]) {
                        info.displayName = infoPlist[@"CFBundleName"];
                    }
                    if (infoPlist[@"CFBundleIdentifier"]) {
                        info.bundleIdentifier = infoPlist[@"CFBundleIdentifier"];
                    }
                }

                if ([UIImage respondsToSelector:@selector(_applicationIconImageForBundleIdentifier:format:scale:)]) {
                    info.appIcon = [UIImage _applicationIconImageForBundleIdentifier:info.bundleIdentifier
                                                                          format:0
                                                                           scale:[UIScreen mainScreen].scale];
                }
            }
        }

        // Count active L4 TCP/UDP sockets for this PID
        uint32_t tcpCount = 0, udpCount = 0;
        [self countSocketsForPID:pid outTCP:&tcpCount outUDP:&udpCount];
        info.tcpSocketCount = tcpCount;
        info.udpSocketCount = udpCount;

        // Apply search query filter
        if (searchQuery.length > 0) {
            NSString *q = [searchQuery lowercaseString];
            BOOL matchName = [[info.displayName lowercaseString] containsString:q] ||
                             [[info.processName lowercaseString] containsString:q] ||
                             [[info.bundleIdentifier lowercaseString] containsString:q] ||
                             [[NSString stringWithFormat:@"%d", info.pid] containsString:q];
            if (!matchName) continue;
        }

        [result addObject:info];
    }

    free(procs);

    // Sort: User apps first, then processes with active sockets, then by name
    [result sortUsingComparator:^NSComparisonResult(AetherProcessInfo *a, AetherProcessInfo *b) {
        if (a.isUserApp != b.isUserApp) {
            return a.isUserApp ? NSOrderedAscending : NSOrderedDescending;
        }
        uint32_t aSockets = a.tcpSocketCount + a.udpSocketCount;
        uint32_t bSockets = b.tcpSocketCount + b.udpSocketCount;
        if (aSockets != bSockets) {
            return (aSockets > bSockets) ? NSOrderedAscending : NSOrderedDescending;
        }
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];

    return result;
}

- (void)countSocketsForPID:(pid_t)pid outTCP:(uint32_t *)outTCP outUDP:(uint32_t *)outUDP {
    uint32_t tcp = 0, udp = 0;
    int bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufSize > 0) {
        struct aether_proc_fdinfo *fds = (struct aether_proc_fdinfo *)malloc(bufSize);
        if (fds) {
            int actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufSize);
            int fdCount = actual / sizeof(struct aether_proc_fdinfo);
            for (int i = 0; i < fdCount; i++) {
                if (fds[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
                    struct aether_socket_fdinfo sockInfo;
                    int rc = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &sockInfo, sizeof(sockInfo));
                    if (rc == sizeof(sockInfo)) {
                        int fam = sockInfo.psi.soi_family;
                        if (fam == AF_INET || fam == AF_INET6) {
                            if (sockInfo.psi.soi_type == SOCK_STREAM) tcp++;
                            else if (sockInfo.psi.soi_type == SOCK_DGRAM) udp++;
                        }
                    }
                }
            }
            free(fds);
        }
    }
    if (outTCP) *outTCP = tcp;
    if (outUDP) *outUDP = udp;
}

- (void)refreshSocketTelemetryForPID:(pid_t)pid {
    AetherSharedState *state = AetherGetSharedState();
    if (!state || pid <= 0) return;

    AetherPortSet ports;
    uint32_t tcp = 0, udp = 0;
    AetherRefreshSocketInventory(pid, &ports, &tcp, &udp, state);
}

#pragma mark - Capture lanes

// P3 — kernel tap.  `primary` = the tap is the only source of truth, so it
// feeds the shared totals; when the in-process lanes are live we still run it
// (it is free visibility and a cross-check) but it only feeds kernelTap*.
- (BOOL)startKernelTapForPID:(pid_t)pid primary:(BOOL)primary
                       error:(NSError * _Nullable * _Nullable)error {
    char errBuf[256] = {0};
    // /dev/bpf and proc_pidfdinfo() on another process both need root.  The
    // HUD daemon has it (persona spawn); the UI app runs as uid 501 and must
    // delegate to a root copy of itself.
    int rc = (geteuid() == 0)
        ? AetherKernelLaneStart(pid, primary, errBuf, sizeof(errBuf))
        : AetherKernelLaneStartViaRootHelper(pid, primary, errBuf, sizeof(errBuf));
    if (rc != 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"AetherKernelLane" code:rc
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:errBuf]}];
        }
        AetherLog(@"kernel tap failed for pid %d: %s", pid, errBuf);
        return NO;
    }
    AetherLog(@"kernel tap STARTED for pid %d (primary=%d)", pid, primary ? 1 : 0);
    return YES;
}

- (void)stopKernelTap {
    AetherKernelLaneStopRootHelper();
    AetherKernelLaneStop();
    AetherLog(@"kernel tap STOPPED");
}

// P1+P2 — in-process lanes: dlopen the payload, then hand it our shared state
- (BOOL)injectIntoProcess:(AetherProcessInfo *)processInfo
                error:(NSError * _Nullable * _Nullable)error {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return NO;

    AetherResetTelemetryForNewTarget(
        state,
        processInfo.pid,
        [processInfo.displayName UTF8String],
        [processInfo.bundleIdentifier UTF8String],
        [processInfo.executablePath UTF8String]
    );

    // Stage dylib to world-readable path
    NSString *bundledDylib = [[NSBundle mainBundle] pathForResource:@"libNetHookPayload" ofType:@"dylib"];
    if (bundledDylib) {
        [[NSFileManager defaultManager] copyItemAtPath:bundledDylib
                                                toPath:@AETHER_DYLIB_INSTALL_PATH
                                                 error:nil];
        chmod(AETHER_DYLIB_INSTALL_PATH, 0755);
    }

    // Attempt in-process injection (P1+P2)
    char errBuf[256] = {0};
    int injectRC = AetherInjectAndArm(processInfo.pid, AETHER_DYLIB_INSTALL_PATH, errBuf, sizeof(errBuf));
    AetherLog(@"Mach inject pid %d rc=%d err=[%s]", processInfo.pid, injectRC, errBuf);

    if (injectRC == 0) {
        aether_atomic_store(&state->isInjected, true);
        aether_atomic_store(&state->injectionMethod, AetherMethodInProcess);
        aether_atomic_store(&state->availableLanes,
                            (uint32_t)(AetherLaneBSDSocket | AetherLaneLibnetwork));
        [self writeEngineStatus:@"In-process hooks (P1 BSD + P2 libnetwork)"];
    } else {
        aether_atomic_store(&state->isInjected, false);
        aether_atomic_store(&state->injectionMethod, AetherMethodNone);
        [self writeEngineStatus:[NSString stringWithFormat:
                                 @"Injection unavailable (%s)", errBuf]];
        AetherLog(@"Injection failed — kernel tap / shaper lanes will carry the session");
    }

    AetherLog(@"attach pid %d name=%s bundle=%s", processInfo.pid,
              processInfo.processName.UTF8String ?: "?",
              processInfo.bundleIdentifier.UTF8String ?: "?");
    [self refreshSocketTelemetryForPID:processInfo.pid];
    notify_post(kAetherNotifyStateChanged);
    return YES;
}

- (void)detachFromCurrentProcess {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    aether_atomic_store(&state->interceptionActive, false);
    aether_atomic_store(&state->isInjected, false);
    aether_atomic_store(&state->targetPID, 0);
    aether_atomic_store(&state->injectionMethod, AetherMethodNone);
    aether_atomic_store(&state->activeLanes, 0);

    [self stopKernelTap];
    char flushErr[256] = {0};
    AetherShaperFlush(flushErr, sizeof(flushErr));

    notify_post(kAetherNotifyFlushQueue);
    notify_post(kAetherNotifyStateChanged);
}

#pragma mark - Process liveness (zombie aware)

// A child that has exited but has not been waitpid()'ed is STILL a process:
// kill(pid, 0) succeeds on it.  Every "is the daemon running?" check in this
// file therefore answered YES for a corpse, which is exactly how the floating
// button could be gone while the UI kept offering "Remove floating button" —
// and worse, the corpse also made every freshly spawned daemon quit instantly,
// because the single-instance guard saw an "alive" pid in the pid file.
//
// Returns: 0 = gone, 1 = alive, 2 = exited but not reaped (zombie).
int AetherPIDStateOf(pid_t pid) {
    if (pid <= 0) return 0;
#ifndef SZOMB
#define SZOMB 4
#endif
    struct kinfo_proc kp;
    memset(&kp, 0, sizeof(kp));
    size_t len = sizeof(kp);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && len > 0) {
        return (kp.kp_proc.p_stat == SZOMB) ? 2 : 1;
    }
    // sysctl refused (sandbox / not our process): fall back to signal 0.
    // EPERM means "exists and is more privileged", i.e. alive.
    if (kill(pid, 0) == 0 || errno == EPERM) return 1;
    return 0;
}

static pid_t AetherHUDPidFromFile(void) {
    NSString *pidStr = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
    return (pid_t)[pidStr intValue];
}

#pragma mark - HUD supervision

// The HUD daemon is a spawned root plugin process: it can be killed by jetsam,
// by a SpringBoard relaunch, or by iOS suspending/reaping it — in every one of
// those cases it dies WITHOUT a log line, and the floating button simply
// disappears (which is exactly what the 4.0.6/4.0.7 logs showed: the next
// toggle reported running=0).  Nothing supervised it, so nothing brought it
// back.  This timer is that supervisor: while the user wants the HUD, it must
// exist.
static dispatch_source_t gHUDWatchdog = NULL;
static CFTimeInterval    gHUDLastRespawn = 0;
static int               gHUDRespawnBurst = 0;

- (void)startHUDWatchdog {
    if (gHUDWatchdog) return;
    gHUDWatchdog = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                          dispatch_get_main_queue());
    dispatch_source_set_timer(gHUDWatchdog, DISPATCH_TIME_NOW,
                              (int64_t)(2.0 * NSEC_PER_SEC),
                              (int64_t)(0.5 * NSEC_PER_SEC));
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(gHUDWatchdog, ^{
        [weakSelf hudWatchdogTick];
    });
    dispatch_resume(gHUDWatchdog);
}

// Reap the HUD daemon if it is our child: until it is reaped it stays a
// zombie, and a zombie is indistinguishable from a live process for every
// check in this file.  Reaping it here also tells us HOW it died, which is
// the one piece of evidence a silently vanishing button never gave us.
- (void)reapHUDChild {
    pid_t hudPID = AetherHUDPidFromFile();
    if (hudPID <= 0) return;
    int status = 0;
    pid_t r = waitpid(hudPID, &status, WNOHANG);
    if (r != hudPID) return;                       // not ours, or still running
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        const char *why = (sig == SIGKILL) ? "SIGKILL (jetsam / iOS watchdog / external kill)"
                        : (sig == SIGSEGV) ? "SIGSEGV (crash)"
                        : (sig == SIGBUS)  ? "SIGBUS (crash)"
                        : (sig == SIGABRT) ? "SIGABRT (abort)"
                        : strsignal(sig);
        AetherLog(@"HUD daemon pid %d died from signal %d — %s", hudPID, sig, why ? why : "?");
    } else if (WIFEXITED(status)) {
        AetherLog(@"HUD daemon pid %d exited with status %d", hudPID, WEXITSTATUS(status));
    }
}

// Ask a short-lived root copy of ourselves to SIGKILL the HUD: a uid-501 app
// cannot signal a uid-0 process (EPERM), which is why "Stop" used to leave
// the daemon running.
- (void)killHUDProcess {
    uint32_t execSize = 0;
    _NSGetExecutablePath(NULL, &execSize);
    char *execPath = (char *)calloc(1, execSize + 1);
    _NSGetExecutablePath(execPath, &execSize);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#if !TARGET_OS_SIMULATOR
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
#endif
    pid_t childPID = 0;
    const char *args[] = { execPath, "-exit", NULL };
    int rc = posix_spawn(&childPID, execPath, NULL, &attr, (char **)args, environ);
    AetherLog(@"HUD -exit verb rc=%d", rc);
    if (rc == 0) {
        int st = 0;
        waitpid(childPID, &st, 0);          // do not leave a second zombie behind
    }
    posix_spawnattr_destroy(&attr);
    free(execPath);
}

- (void)hudWatchdogTick {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    // The user turned the HUD off: nothing to supervise.
    if (!aether_atomic_load(&state->hudVisible)) { gHUDRespawnBurst = 0; return; }

    [self reapHUDChild];

    CFTimeInterval now = CFAbsoluteTimeGetCurrent();

    if ([self isGlobalFloatingHUDRunning]) {
        // Alive, but silent for a long time = wedged: the main thread is
        // blocked (a lane start that never returns) or the run loop never
        // came up.  A wedged HUD shows a button that does nothing, so it has
        // to go — but only through the root -exit verb.
        uint64_t hb   = aether_atomic_load(&state->hudHeartbeatTs);
        uint64_t wall = (uint64_t)time(NULL);
        bool silent = (hb > 0) ? ((wall - hb) > 8)
                               : (gHUDLastRespawn > 0 && (now - gHUDLastRespawn) > 12.0);
        if (silent) {
            static CFTimeInterval gHUDLastWedgeKill = 0;
            if (now - gHUDLastWedgeKill > 15.0) {
                gHUDLastWedgeKill = now;
                pid_t p = AetherHUDPidFromFile();
                AetherLog(@"HUD daemon pid %d is alive but silent (heartbeat age %llus) — "
                          @"wedged, killing it", (int)p,
                          (unsigned long long)(hb > 0 ? (wall - hb) : 0));
                [self killHUDProcess];
                [self reapHUDChild];
                gHUDLastRespawn = now;      // do not immediately respawn on top of it
            }
        }
        gHUDRespawnBurst = 0;
        return;
    }

    if (now - gHUDLastRespawn < 4.0) return;          // give the spawn a moment
    if (gHUDRespawnBurst >= 6) {                      // dying in a tight loop
        static CFTimeInterval gHUDLastWarn = 0;
        if (now - gHUDLastWarn > 60.0) {
            gHUDLastWarn = now;
            AetherLog(@"HUD daemon keeps dying (%d restarts) — backing off to one retry "
                      @"per minute; check for jetsam / a SpringBoard loop", gHUDRespawnBurst);
        }
        if (now - gHUDLastRespawn < 60.0) return;
        gHUDRespawnBurst = 0;
    }

    gHUDLastRespawn = now;
    gHUDRespawnBurst++;
    AetherLog(@"HUD daemon vanished without an exit log (attempt %d) — respawning",
              gHUDRespawnBurst);
    [self setGlobalFloatingHUDEnabled:YES];
}

#pragma mark - Global Root Floating HUD Button Management

- (BOOL)isGlobalFloatingHUDRunning {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        uint64_t hb = aether_atomic_load(&state->hudHeartbeatTs);
        if (hb > 0 && (uint64_t)time(NULL) - hb <= 3) return YES;
    }

    NSString *pidStr = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                                 encoding:NSUTF8StringEncoding
                                                    error:nil];
    if (pidStr.length) {
        pid_t hudPID = (pid_t)[pidStr intValue];
        // 2 == zombie: the process is gone, only its exit status is waiting to
        // be collected.  Treating that as "running" is what made the UI offer
        // "Remove floating button" for a button that was no longer on screen.
        if (AetherPIDStateOf(hudPID) == 1) return YES;
    }
    return NO;
}

- (void)setGlobalFloatingHUDEnabled:(BOOL)enabled {
    AetherSharedState *state = AetherGetSharedState();

    uint32_t execSize = 0;
    _NSGetExecutablePath(NULL, &execSize);
    char *execPath = (char *)calloc(1, execSize + 1);
    _NSGetExecutablePath(execPath, &execSize);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

#if !TARGET_OS_SIMULATOR
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
#endif

    if (enabled) {
        if ([self isGlobalFloatingHUDRunning]) {
            free(execPath);
            posix_spawnattr_destroy(&attr);
            return;
        }

        posix_spawnattr_setpgroup(&attr, 0);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);

        if (state) {
            aether_atomic_store(&state->hudCommand, 0);
            aether_atomic_store(&state->hudHeartbeatTs, 0);
        }
        pid_t childPID = 0;
        const char *args[] = { execPath, "-hud", NULL };
        int rc = posix_spawn(&childPID, execPath, NULL, &attr, (char **)args, environ);
        AetherLog(@"spawn HUD daemon rc=%d pid=%d", rc, rc == 0 ? childPID : -1);
        if (rc == 0 && state) {
            aether_atomic_store(&state->hudVisible, true);
            // From now on its existence is supervised: a silent death gets
            // noticed within two seconds instead of at the next tap.
            [self startHUDWatchdog];
            // ... but not *immediately*: the child needs ~300 ms to write its
            // pid file and up to a second to publish its first heartbeat, and
            // a tick landing inside that window sees "not running" and spawns
            // a second daemon (4.0.8 log: spawned 93349, respawned 93350 64 ms
            // later while 93349 was alive and well).
            gHUDLastRespawn = CFAbsoluteTimeGetCurrent();
        }
    } else {
        // Graceful exit via shm command
        if (state) {
            aether_atomic_store(&state->hudCommand, 1);
            aether_atomic_store(&state->hudHeartbeatTs, 0);
            aether_atomic_store(&state->hudVisible, false);
            aether_atomic_store(&state->interceptionActive, false);
            AetherLog(@"HUD remove command sent (graceful exit)");
            pid_t fp = aether_atomic_load(&state->rootFrozenPid);
            if (fp > 0) { kill(fp, SIGCONT); aether_atomic_store(&state->rootFrozenPid, 0);
                          AetherLog(@"unfroze pid %d on HUD remove", fp); }
        }
        notify_post(kAetherNotifyHUDToggle);

        // Fallback: legacy -exit
        pid_t childPID = 0;
        const char *args[] = { execPath, "-exit", NULL };
        int rc = posix_spawn(&childPID, execPath, NULL, &attr, (char **)args, environ);
        if (rc == 0) {
            // Reap it: an un-waited child is a zombie that keeps its pid
            // alive, and a live-looking pid is exactly what made this app
            // believe a dead daemon was still running.
            int st = 0;
            waitpid(childPID, &st, 0);
        }
    }

    posix_spawnattr_destroy(&attr);
    free(execPath);
    notify_post(kAetherNotifyStateChanged);
}

- (void)writeEngineStatus:(NSString *)text {
    AetherSharedState *state = AetherGetSharedState();
    if (!state || text.length == 0) return;
    strncpy(state->engineStatus, [text UTF8String], sizeof(state->engineStatus) - 1);
    state->engineStatus[sizeof(state->engineStatus) - 1] = '\0';
}

/// One-shot device capability probe.  Cheap enough to run at every start; the
/// result is what the Home tab shows under the target box.
- (uint32_t)probeAvailableLanes {
    AetherSharedState *state = AetherGetSharedState();
    uint32_t lanes = 0;

    uint32_t shaperCaps = AetherShaperCapabilities();
    // AETHER_SHAPER_CAP_FREEZE means "we can spawn a root copy of ourselves",
    // which is also exactly what the tap needs when we are not root already.
    bool canGoRoot = (shaperCaps & AETHER_SHAPER_CAP_FREEZE) != 0;
    if (AetherKernelLaneIsAvailable() || canGoRoot) lanes |= AetherLaneKernelTap;

    if (shaperCaps & (AETHER_SHAPER_CAP_PFCTL | AETHER_SHAPER_CAP_FREEZE)) {
        lanes |= AetherLaneShaper;
    }

    // P1/P2 are only "available" once a dylib has actually been accepted by the
    // target, which we cannot know in advance — the arbiter records them when
    // (and if) injection succeeds.
    if (state && aether_atomic_load(&state->isInjected)) {
        lanes |= (AetherLaneBSDSocket | AetherLaneLibnetwork);
    }
    if (state) aether_atomic_store(&state->availableLanes, lanes);
    return lanes;
}

- (void)startCaptureLanesForPID:(pid_t)targetPID {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    uint32_t available = [self probeAvailableLanes];

    // --- Refresh the socket inventory first: every lane keys off it ---------
    [self refreshSocketTelemetryForPID:targetPID];

    // --- P1 + P2: in-process hooks -----------------------------------------
    NSString *bundled = [[NSBundle mainBundle] pathForResource:@"libNetHookPayload" ofType:@"dylib"];
    if (bundled) {
        [[NSFileManager defaultManager] copyItemAtPath:bundled
                                                toPath:@AETHER_DYLIB_INSTALL_PATH
                                                 error:nil];
        chmod(AETHER_DYLIB_INSTALL_PATH, 0755);
    }

    char injectErr[256] = {0};
    int injectRC = AetherInjectAndArm(targetPID, AETHER_DYLIB_INSTALL_PATH,
                                      injectErr, sizeof(injectErr));
    AetherLog(@"inject pid %d rc=%d err=[%s]", targetPID, injectRC, injectErr);

    BOOL injected = (injectRC == 0);
    aether_atomic_store(&state->isInjected, injected);

    uint32_t activeLanes = 0;

    // --- P3: kernel tap -----------------------------------------------------
    // primary == !injected: when the hooks are live the tap is only a
    // cross-check, otherwise it is the only source of visibility we have.
    char tapErr[256] = {0};
    int tapRC = 0;
    if (geteuid() == 0) {
        tapRC = AetherKernelLaneStart(targetPID, !injected, tapErr, sizeof(tapErr));
    } else {
        tapRC = AetherKernelLaneStartViaRootHelper(targetPID, !injected, tapErr, sizeof(tapErr));
    }
    BOOL tapRunning = (tapRC == 0);
    if (tapRunning) {
        activeLanes |= AetherLaneKernelTap;
        AetherLog(@"kernel tap active (primary=%d)", injected ? 0 : 1);
    } else {
        AetherLog(@"kernel tap unavailable: %s", tapErr);
    }

    if (injected) {
        activeLanes |= (AetherLaneBSDSocket | AetherLaneLibnetwork);
    }

    // --- P4: enforcement ----------------------------------------------------
    // The in-process lanes can hold/drop/tamper on their own.  Without them we
    // need the kernel side (PF/dummynet/freeze) to have any effect at all.
    // Observe mode deliberately starts NONE of it: the user wants to watch the
    // target's traffic, and the only primitive iOS offers (SIGSTOP) would stop
    // the target from generating any traffic at all.
    AetherInterceptMode mode = (AetherInterceptMode)aether_atomic_load(&state->interceptMode);

    // 4.1.5 — be honest about what this device can actually enforce instead of
    // logging "shaper failed" on every single session.  Delay/Tamper need a
    // queue (dummynet/PF) or an in-process hook; Hold/Drop can additionally be
    // faked with SIGSTOP, but only when the user opted into freezing.
    uint32_t shaperCaps = AetherShaperCapabilities();
    BOOL canQueue     = injected ||
                        (shaperCaps & (AETHER_SHAPER_CAP_PFCTL | AETHER_SHAPER_CAP_DUMMYNET)) != 0;
    BOOL canHoldOrDrop = canQueue ||
                        (aether_atomic_load(&state->allowFreeze) &&
                         (shaperCaps & AETHER_SHAPER_CAP_FREEZE));
    BOOL modeUsable = (mode == AetherModeObserve) ||
                      ((mode == AetherModeHoldQueue || mode == AetherModeDropPacket)
                           ? canHoldOrDrop : canQueue);
    if (!modeUsable) {
        AetherLog(@"mode %u cannot be enforced on this device (pfctl=%d dnctl=%d injected=%d "
                  @"freeze=%d) - falling back to Observe (capture only)",
                  (unsigned)mode,
                  (shaperCaps & AETHER_SHAPER_CAP_PFCTL) ? 1 : 0,
                  (shaperCaps & AETHER_SHAPER_CAP_DUMMYNET) ? 1 : 0,
                  injected ? 1 : 0,
                  aether_atomic_load(&state->allowFreeze));
        aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeObserve);
        mode = AetherModeObserve;
    }

    if (!injected && mode == AetherModeObserve) {
        AetherLog(@"observe mode — no enforcement lane (capture only, target untouched)");
    } else if (!injected) {
        if (available & AetherLaneShaper) {
            char shapeErr[256] = {0};
            int shapeRC = AetherShaperApply(targetPID, shapeErr, sizeof(shapeErr));
            if (shapeRC == 0) {
                activeLanes |= AetherLaneShaper;
            } else if (shapeRC == -7) {
                // Not a failure: freezing the target is opt-in and it is off,
                // so there is simply nothing to enforce.  Capture continues.
                AetherLog(@"%s", shapeErr);
            } else {
                AetherLog(@"shaper failed: %s", shapeErr);
            }
        } else {
            AetherLog(@"no enforcement primitive on this device — observe only");
        }
    }

    // --- Ping simulation (lag switch) ---------------------------------------
    // Independent of the intercept mode: it is the only way to move a game's
    // ping on a device with no pfctl/dnctl and no injection.  The worker stays
    // idle (never signals the target) while lagSpikeMs == 0.
    if (shaperCaps & AETHER_SHAPER_CAP_FREEZE) {
        char lagErr[256] = {0};
        if (AetherLagSwitchStart(targetPID, lagErr, sizeof(lagErr)) == 0) {
            if (aether_atomic_load(&state->lagSpikeMs) > 0) {
                activeLanes |= AetherLaneShaper;
            }
        } else {
            AetherLog(@"ping simulation unavailable: %s", lagErr);
        }
    }

    aether_atomic_store(&state->activeLanes, activeLanes);
    aether_atomic_store(&state->laneOwnerPID, getpid());

    // --- Method + human readable summary ------------------------------------
    AetherCaptureMethod method;
    NSString *summary;
    if (injected && tapRunning) {
        method  = AetherMethodFull;
        summary = @"In-process hooks + BPF tap";
    } else if (injected) {
        method  = AetherMethodInProcess;
        summary = @"In-process hooks (BSD + libnetwork)";
    } else if (tapRunning && (activeLanes & AetherLaneShaper)) {
        method  = AetherMethodTapAndShaper;
        summary = [NSString stringWithFormat:@"BPF tap on %s + PF/freeze",
                   state->kernelTapInterface[0] ? state->kernelTapInterface : "?"];
    } else if (tapRunning) {
        method  = AetherMethodKernelTap;
        NSString *why = @"capture only — traffic untouched";
        if (mode != AetherModeObserve) {
            why = (aether_atomic_load(&state->allowFreeze) != 0)
                ? @"capture only — no enforcement primitive on this device"
                : @"capture only — this mode needs freeze, which is OFF (Settings)";
        }
        summary = [NSString stringWithFormat:@"BPF tap on %s (%@)",
                   state->kernelTapInterface[0] ? state->kernelTapInterface : "?", why];
    } else if (activeLanes & AetherLaneShaper) {
        method  = AetherMethodShaper;
        summary = @"PF / freeze only (no packet visibility)";
    } else {
        method  = AetherMethodNone;
        summary = @"No lane available — check root & entitlements";
    }
    aether_atomic_store(&state->injectionMethod, (uint8_t)method);
    [self writeEngineStatus:summary];
    AetherLog(@"lanes=%u method=%u — %@", activeLanes, (unsigned)method, summary);
}

- (void)stopCaptureLanes {
    AetherSharedState *state = AetherGetSharedState();

    // Only the owner tears the lanes down; a second process stopping them
    // would rip out a tap that is still in use.
    if (state) {
        pid_t owner = aether_atomic_load(&state->laneOwnerPID);
        if (owner != 0 && owner != getpid() && (kill(owner, 0) == 0 || errno == EPERM)) {
            AetherLog(@"lanes belong to pid %d — not stopping them from pid %d",
                      owner, getpid());
            return;
        }
        aether_atomic_store(&state->laneOwnerPID, 0);
    }

    [self stopKernelTap];
    AetherLagSwitchStop();

    char flushErr[256] = {0};
    if (AetherShaperFlush(flushErr, sizeof(flushErr)) != 0) {
        AetherLog(@"shaper flush: %s", flushErr);
    }

    if (state) {
        aether_atomic_store(&state->activeLanes, 0);
        aether_atomic_store(&state->injectionMethod, AetherMethodNone);
        aether_atomic_store(&state->isInjected, false);
    }
}

// Starting the lanes means: probe the device (spawn a root child and wait for
// it), try an injection, then bring up the BPF tap with a 1-second liveness
// probe inside it.  That is seconds of work — on the HUD daemon's main thread
// it blocks the run loop, the heartbeat stops, and iOS kills an unresponsive
// process outright (0x8badf00d), which is a SIGKILL with no log line at all.
// "I turned interception on and the button disappeared a few seconds later"
// is that kill.  Everything heavy goes to this serial queue from now on.
static dispatch_queue_t AetherLaneQueue(void) {
    static dispatch_queue_t q = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        q = dispatch_queue_create("com.aethernet.lanes", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

// Resume a capture after the daemon was restarted.  Two things make this more
// than a call to -startCaptureLanesForPID::
//   * it has to wait for the run loop to be up, so it is deferred — and by the
//     time it runs the user may have turned interception OFF (4.1.0 log: STOP
//     at 11:27:18.828, then the deferred resume started a fresh tap at
//     11:27:20.785 on top of the one STOP had just torn down);
//   * it must be serialised with start/stop, so it runs on the lane queue.
- (void)resumeCaptureForPID:(pid_t)pid {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   AetherLaneQueue(), ^{
        @autoreleasepool {
            AetherSharedState *st = AetherGetSharedState();
            if (!st) return;
            if (!aether_atomic_load(&st->interceptionActive)) {
                AetherLog(@"resume skipped — interception was switched off while "
                          @"the daemon was starting");
                return;
            }
            pid_t owner = (pid_t)aether_atomic_load(&st->laneOwnerPID);
            if (owner != 0 && owner != getpid() && AetherPIDStateOf(owner) == 1) {
                AetherLog(@"resume skipped — pid %d already owns the lanes", owner);
                return;
            }
            [self startCaptureLanesForPID:pid];
        }
    });
}

- (void)setInterceptionActive:(BOOL)active {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    bool wasActive = aether_atomic_exchange(&state->interceptionActive, active);
    AetherLog(@"interception %@ (was %d)", active ? @"START" : @"STOP", wasActive);

    if (active) {
        pid_t targetPID = aether_atomic_load(&state->targetPID);
        if (targetPID > 0) {
            // Immediate feedback: the button must not look dead while the
            // lanes are still coming up on the background queue.
            [self writeEngineStatus:@"Starting capture…"];
            notify_post(kAetherNotifyStateChanged);
            dispatch_async(AetherLaneQueue(), ^{
                @autoreleasepool {
                    [self startCaptureLanesForPID:targetPID];
                }
                notify_post(kAetherNotifyConfigChanged);
                notify_post(kAetherNotifyStateChanged);
            });
        } else {
            AetherLog(@"interception requested but no target selected");
            [self writeEngineStatus:@"No target selected"];
            notify_post(kAetherNotifyConfigChanged);
            notify_post(kAetherNotifyStateChanged);
        }
    } else {
        notify_post(kAetherNotifyFlushQueue);   // release anything held
        notify_post(kAetherNotifyStateChanged);
        dispatch_async(AetherLaneQueue(), ^{
            @autoreleasepool {
                [self stopCaptureLanes];
            }
            notify_post(kAetherNotifyStateChanged);
        });
    }
}

@end