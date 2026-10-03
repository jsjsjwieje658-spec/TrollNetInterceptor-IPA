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

/// Starts NECP kernel-level packet capture (Tier 0) — no injection required
- (BOOL)startNECPCaptureForPID:(pid_t)pid error:(NSError * _Nullable * _Nullable)error;

/// Stops NECP capture
- (void)stopNECPCapture;

/// Detaches hooks and flushes held packet queues
- (void)detachFromCurrentProcess;

/// Spawns or terminates the global root Floating HUD Button daemon
- (void)setGlobalFloatingHUDEnabled:(BOOL)enabled;
- (BOOL)isGlobalFloatingHUDRunning;

/// Toggles active packet interception (Play ▶ <-> Pause ⏸)
- (void)setInterceptionActive:(BOOL)active;

@end

NS_ASSUME_NONNULL_END