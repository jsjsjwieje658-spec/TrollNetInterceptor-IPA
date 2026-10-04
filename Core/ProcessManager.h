//
//  ProcessManager.h
//  AetherNet — Process Discovery, Socket Inspector & PID Injection Engine
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include "../headers/AetherNetShared.h"

NS_ASSUME_NONNULL_BEGIN

@interface AetherProcessInfo : NSObject
@property (nonatomic, assign) pid_t pid;
@property (nonatomic, assign) pid_t ppid;
@property (nonatomic, assign) uid_t uid;
@property (nonatomic, copy) NSString *processName;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *executablePath;
@property (nonatomic, assign) BOOL isUserApp;
@property (nonatomic, assign) uint32_t tcpSocketCount;
@property (nonatomic, assign) uint32_t udpSocketCount;
@property (nonatomic, strong, nullable) UIImage *appIcon;
@end

@interface AetherProcessManager : NSObject

+ (instancetype)sharedManager;

/// Enumerates running processes (prioritizing user apps & active network processes)
- (NSArray<AetherProcessInfo *> *)enumerateRunningProcessesWithFilter:(nullable NSString *)searchQuery
                                                         onlyUserApps:(BOOL)onlyUserApps;

/// Inspects live L4 TCP/UDP file descriptors of a target PID via XNU libproc SPI
- (void)refreshSocketTelemetryForPID:(pid_t)pid;

/// Injects libNetHookPayload.dylib into target PID and binds L4 TCP/UDP hooks (Tier 1)
- (BOOL)injectIntoProcess:(AetherProcessInfo *)processInfo
                error:(NSError * _Nullable * _Nullable)error;

/// Starts the P3 kernel tap (/dev/bpf).  `primary` marks it as the only
/// source of truth for the shared traffic counters.
- (BOOL)startKernelTapForPID:(pid_t)pid primary:(BOOL)primary
                       error:(NSError * _Nullable * _Nullable)error;

/// Stops the P3 kernel tap
- (void)stopKernelTap;

/// Probes what this device can actually do and stores it in ->availableLanes
- (uint32_t)probeAvailableLanes;

/// Starts every lane the device supports for the current target
- (void)startCaptureLanesForPID:(pid_t)targetPID;

/// Stops every lane and releases frozen targets
- (void)stopCaptureLanes;

/// Detaches hooks and flushes held packet queues
- (void)detachFromCurrentProcess;

/// Spawns or terminates the global root Floating HUD Button daemon
- (void)setGlobalFloatingHUDEnabled:(BOOL)enabled;
- (BOOL)isGlobalFloatingHUDRunning;
/// Supervises the HUD daemon: while the user wants the floating button, this
/// respawns it when it dies without a log line (jetsam / SpringBoard relaunch).
/// Process liveness that knows about zombies: 0 = gone, 1 = alive,
/// 2 = exited but not reaped (still visible to kill(), but not running).
int AetherPIDStateOf(pid_t pid);

- (void)startHUDWatchdog;
/// Reap the HUD daemon if it is our child and log how it died.
- (void)reapHUDChild;
/// SIGKILL the HUD through a short-lived root copy of ourselves.
- (void)killHUDProcess;

/// Toggles active packet interception (Play ▶ <-> Pause ⏸)
- (void)setInterceptionActive:(BOOL)active;
/// Restart the lanes for `pid` after a daemon restart (deferred, lane-queue
/// serialised, cancelled if interception was switched off in the meantime).
- (void)resumeCaptureForPID:(pid_t)pid;

@end

NS_ASSUME_NONNULL_END