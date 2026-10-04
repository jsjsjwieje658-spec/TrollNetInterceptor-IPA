//
//  MainApp.mm
//  AetherNet — Normal UIApplication Entry (Main App UI)
//
//  Registers a UIApplication subclass without UIScene (required for HUD-style
//  TrollStore apps on iOS 13+) and hosts the 2-tab root TabBarController:
//    Tab 1 — Home       (PID picker box · L4 TCP/UDP status · HUD spawn)
//    Tab 2 — Settings   (capture rules · network simulation · HUD size)
//

#import <UIKit/UIKit.h>
#import "../Core/AetherLog.h"
#import <notify.h>
#import <time.h>
#import "../headers/AetherNetShared.h"
#import "HomeViewController.h"
#import "LogViewController.h"
#import "SettingsViewController.h"
#import "AppTheme.h"
#import "../Core/ProcessManager.h"

#pragma mark - Scene-bypass UIApplication (iOS 13+ TrollStore)

@interface AetherMainApplication : UIApplication
@end

@implementation AetherMainApplication
// Returning YES for _shouldOverrideCallStack... is unnecessary; simply not
// implementing UIApplicationSceneManifest-based bootstrap avoids UIScene entirely.
@end

#pragma mark - Rate Ticker & Auto Flush

@interface AetherEngineCoordinator : NSObject
@property (nonatomic, strong) NSTimer *ticker;
@end

@implementation AetherEngineCoordinator {
    uint64_t _lastRXBytes;
    uint64_t _lastTXBytes;
    NSTimeInterval _lastFlushTime;
}

+ (instancetype)shared {
    static AetherEngineCoordinator *c = nil;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ c = [[AetherEngineCoordinator alloc] init]; });
    return c;
}

- (void)start {
    __weak typeof(self) weakSelf = self;
    self.ticker = [NSTimer timerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [weakSelf tick];
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.ticker forMode:NSRunLoopCommonModes];
}

- (void)tick {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    NSTimeInterval now = [NSDate date].timeIntervalSince1970;

    // --- 1. Live rate computation (bytes delta per second) ---
    uint64_t rx = aether_atomic_load(&state->totalBytesRX);
    uint64_t tx = aether_atomic_load(&state->totalBytesTX);
    aether_atomic_store(&state->currentRXRateBps, (uint32_t)(rx > _lastRXBytes ? (rx - _lastRXBytes) : 0));
    aether_atomic_store(&state->currentTXRateBps, (uint32_t)(tx > _lastTXBytes ? (tx - _lastTXBytes) : 0));
    _lastRXBytes = rx;
    _lastTXBytes = tx;

    // --- 2. Per-PID socket telemetry refresh (from XNU libproc SPI) ---
    // Previously this only ran when the dylib had been injected, which meant
    // the socket table (and therefore the PF rule set and the BPF port
    // matcher) went stale exactly in the case where they matter most: no
    // injection.  Refresh whenever we have a target and any lane is live.
    pid_t pid = aether_atomic_load(&state->targetPID);
    if (pid > 0) {
        bool injected  = aether_atomic_load(&state->isInjected);
        bool capturing = aether_atomic_load(&state->interceptionActive);
        uint32_t lanes = aether_atomic_load(&state->activeLanes);
        if (injected || capturing || lanes != 0) {
            [[AetherProcessManager sharedManager] refreshSocketTelemetryForPID:pid];
        }
    }

    // --- 3. Safety auto-flush of held packets (time-based, not count-modulo) ---
    if (aether_atomic_load(&state->interceptionActive)) {
        uint32_t flushAfter = aether_atomic_load(&state->autoFlushSeconds);
        uint64_t held = aether_atomic_load(&state->heldPacketsCount);
        if (flushAfter > 0 && held > 0) {
            if (now - _lastFlushTime >= (NSTimeInterval)flushAfter) {
                _lastFlushTime = now;
                notify_post(kAetherNotifyFlushQueue);
            }
        }
    }
}

@end

#pragma mark - Root Tab Bar Controller

@interface AetherTabBarController : UITabBarController
@end

@implementation AetherTabBarController

- (void)viewDidLoad {
    [super viewDidLoad];

    HomeViewController *home = [[HomeViewController alloc] init];
    UINavigationController *homeNav = [[UINavigationController alloc] initWithRootViewController:home];
    homeNav.navigationBar.barStyle = UIBarStyleBlack;
    homeNav.navigationBar.tintColor = [AppTheme colorGold];
    homeNav.navigationBar.prefersLargeTitles = YES;

    SettingsViewController *settings = [[SettingsViewController alloc] init];
    UINavigationController *settingsNav = [[UINavigationController alloc] initWithRootViewController:settings];
    settingsNav.navigationBar.barStyle = UIBarStyleBlack;
    settingsNav.navigationBar.tintColor = [AppTheme colorGold];
    settingsNav.navigationBar.prefersLargeTitles = YES;

    LogViewController *logVC = [[LogViewController alloc] init];
    UINavigationController *logNav = [[UINavigationController alloc] initWithRootViewController:logVC];
    logNav.navigationBar.barStyle = UIBarStyleBlack;
    logNav.navigationBar.tintColor = [AppTheme colorGold];
    logNav.navigationBar.prefersLargeTitles = YES;

    self.viewControllers = @[homeNav, logNav, settingsNav];
    self.tabBar.barStyle = UIBarStyleBlack;
    self.tabBar.tintColor = [AppTheme colorGold];
    self.tabBar.unselectedItemTintColor = [AppTheme colorTextSecondary];
    self.tabBar.standardAppearance.backgroundColor = [[AppTheme colorObsidian] colorWithAlphaComponent:0.94];
    UITabBarAppearance *tabAppearance = [[UITabBarAppearance alloc] init];
    tabAppearance.backgroundColor = [[AppTheme colorObsidian] colorWithAlphaComponent:0.94];
    tabAppearance.shadowColor = [AppTheme colorCardBorder];
    self.tabBar.standardAppearance = tabAppearance;

    UITabBarItem *homeItem = [[UITabBarItem alloc] initWithTitle:@"Home" image:nil tag:0];
    homeItem.selectedImage = [self systemSymbol:@"bolt.horizontal.fill" fallback:@"⇄"];
    homeItem.image = [self systemSymbol:@"bolt.horizontal" fallback:@"⇄"];

    UITabBarItem *logItem = [[UITabBarItem alloc] initWithTitle:@"Log" image:nil tag:2];
    logItem.selectedImage = [self systemSymbol:@"text.alignleft.fill" fallback:@"📝"];
    logItem.image = [self systemSymbol:@"text.alignleft" fallback:@"📝"];

    UITabBarItem *settingsItem = [[UITabBarItem alloc] initWithTitle:@"Settings" image:nil tag:1];
    settingsItem.image = [self systemSymbol:@"slider.horizontal.3" fallback:@"⚙"];
    settingsItem.selectedImage = [self systemSymbol:@"slider.horizontal.3.fill" fallback:@"⚙"];

    homeNav.tabBarItem = homeItem;
    logNav.tabBarItem = logItem;
    settingsNav.tabBarItem = settingsItem;
}

- (UIImage *)systemSymbol:(NSString *)name fallback:(NSString *)fallback {
    if (@available(iOS 13.0, *)) {
        UIImage *img = [UIImage systemImageNamed:name];
        if (img) return img;
    }
    UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
    fmt.opaque = NO;
    UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(26, 26) format:fmt];
    return [r imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        NSMutableParagraphStyle *p = [NSMutableParagraphStyle new];
        p.alignment = NSTextAlignmentCenter;
        [fallback drawInRect:CGRectMake(0, 2, 26, 22)
              withAttributes:@{
            NSFontAttributeName: [UIFont boldSystemFontOfSize:16],
            NSForegroundColorAttributeName: [UIColor whiteColor],
            NSParagraphStyleAttributeName: p
        }];
    }];
}

@end

#pragma mark - App Delegate

@interface AetherAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AetherAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    AetherLog(@"───────── app didFinishLaunching ─────────");
    AetherLogMergeDaemonLog();
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.backgroundColor = [AppTheme colorObsidian];
    self.window.rootViewController = [[AetherTabBarController alloc] init];
    [self.window makeKeyAndVisible];

    [[AetherEngineCoordinator shared] start];

    // Launch guard: if the app died within 6s on 2+ consecutive launches,
    // skip HUD auto-restore this launch so the user is never locked out.
    NSString *lgPath = @"/var/mobile/Library/Caches/com.aethernet.launchguard";
    NSMutableDictionary *lg = [[[NSDictionary dictionaryWithContentsOfFile:lgPath]
                                mutableCopy] ?: [NSMutableDictionary dictionary] mutableCopy];
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    NSTimeInterval last = [lg[@"ts"] doubleValue];
    int cnt = [lg[@"count"] intValue];
    BOOL crashLoop = (last > 0 && (now - last) < 6.0 && cnt >= 2);
    lg[@"ts"] = @(now);
    lg[@"count"] = @(crashLoop ? 0 : ((now - last) < 6.0 ? cnt + 1 : 0));
    [lg writeToFile:lgPath atomically:YES];

    // Restore HUD daemon if it was enabled before the app was last killed
    AetherSharedState *state = AetherGetSharedState();
    if (state && crashLoop) {
        aether_atomic_store(&state->hudVisible, false); // safe-mode launch
    }
    if (state && aether_atomic_load(&state->hudVisible)) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[AetherProcessManager sharedManager] setGlobalFloatingHUDEnabled:YES];
        });
        // Arm the supervisor even if the spawn above turns out to be a no-op
        // (daemon already running from a previous launch).
        [[AetherProcessManager sharedManager] startHUDWatchdog];
    }

    // Stale-daemon auto-upgrade: the HUD daemon is a spawned root process that
    // SURVIVES app reinstalls, so after an update the old daemon (old touch
    // code) can still be running. The daemon advertises its build number in
    // shm every heartbeat; if it differs from ours, respawn it.
    if (state && !crashLoop) {
        AetherProcessManager *mgr = [AetherProcessManager sharedManager];
        uint32_t db = aether_atomic_load(&state->daemonBuild);
        if (db != AETHER_BUILD_NUM && [mgr isGlobalFloatingHUDRunning]) {
            if (db != 0) {
                // Definitely a different (older) build — swap it now.
                AetherLog(@"stale daemon build %u != app %u — respawning", db, (unsigned)AETHER_BUILD_NUM);
                [mgr setGlobalFloatingHUDEnabled:NO];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    [[AetherProcessManager sharedManager] setGlobalFloatingHUDEnabled:YES];
                });
            } else {
                // 0 = pre-handshake daemon OR fresh spawn not yet ticked —
                // re-check after the next heartbeats.
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    AetherSharedState *s2 = AetherGetSharedState();
                    if (s2 && aether_atomic_load(&s2->daemonBuild) != AETHER_BUILD_NUM &&
                        [[AetherProcessManager sharedManager] isGlobalFloatingHUDRunning]) {
                        AetherLog(@"daemon build still stale after grace — respawning");
                        [[AetherProcessManager sharedManager] setGlobalFloatingHUDEnabled:NO];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                            [[AetherProcessManager sharedManager] setGlobalFloatingHUDEnabled:YES];
                        });
                    }
                });
            }
        }
    }

    return YES;
}

@end

int AetherMainAppMain(int argc, char *argv[])
{
    @autoreleasepool {
        // Kept alive for the lifetime of the app
        return UIApplicationMain(argc, argv, @"AetherMainApplication", @"AetherAppDelegate");
    }
}
