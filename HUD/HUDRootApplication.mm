//
//  HUDRootApplication.mm
//  AetherNet — Entry point & SpringBoard Accessibility Window Host for Global Floating Button
//

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <notify.h>
#include "../headers/AetherNetShared.h"
#include "../headers/PrivateSystemSPI.h"
#import "HUDMainWindow.h"
#import "FloatingToggleButton.h"

@interface AetherHUDViewController : UIViewController
@property (nonatomic, strong) AetherFloatingToggleButton *floatingButton;
@end

@implementation AetherHUDViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor clearColor];

    AetherSharedState *state = AetherGetSharedState();
    CGFloat diameter = state ? (CGFloat)aether_atomic_load(&state->floatingButtonSize) : 58.0;
    CGFloat posX = state ? (CGFloat)aether_atomic_load(&state->floatingPosX) : 320.0;
    CGFloat posY = state ? (CGFloat)aether_atomic_load(&state->floatingPosY) : 220.0;

    // Defensive clamps: stale/garbage shared memory must never produce an
    // off-screen or oversized button.
    CGFloat screenW = self.view.bounds.size.width  ?: [UIScreen mainScreen].bounds.size.width;
    CGFloat screenH = self.view.bounds.size.height ?: [UIScreen mainScreen].bounds.size.height;
    if (!(diameter >= 40.0 && diameter <= 88.0)) diameter = 58.0;
    if (!(posX >= 0 && posX <= screenW))  posX = screenW - diameter / 2.0 - 12.0;
    if (!(posY >= 0 && posY <= screenH))  posY = screenH * 0.42;
    posX = MIN(MAX(posX, diameter / 2.0 + 8.0), screenW - diameter / 2.0 - 8.0);
    posY = MIN(MAX(posY, diameter / 2.0 + 60.0), screenH - diameter / 2.0 - 60.0);

    self.floatingButton = [[AetherFloatingToggleButton alloc] initWithFrame:CGRectMake(0, 0, diameter, diameter)];
    self.floatingButton.center = CGPointMake(posX, posY);
    extern UIView *gAetherFloatingButtonView;
    gAetherFloatingButtonView = self.floatingButton;
    [self.view addSubview:self.floatingButton];

    // Listen for config or state updates from the main app
    __weak typeof(self) weakSelf = self;
    int stateToken = 0, configToken = 0;
    notify_register_dispatch(kAetherNotifyStateChanged, &stateToken, dispatch_get_main_queue(), ^(int token) {
        [weakSelf.floatingButton syncWithSharedStateAnimated:YES];
    });
    notify_register_dispatch(kAetherNotifyConfigChanged, &configToken, dispatch_get_main_queue(), ^(int token) {
        [weakSelf.floatingButton syncWithSharedStateAnimated:YES];
    });
}

@end

@interface AetherHUDApplicationDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) AetherHUDMainWindow *window;
@end

@implementation AetherHUDApplicationDelegate {
    AetherHUDViewController *_rootVC;
    SBSAccessibilityWindowHostingController *_windowHost;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    _rootVC = [[AetherHUDViewController alloc] init];

    self.window = [[AetherHUDMainWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = _rootVC;
    self.window.interactiveFloatingButton = _rootVC.floatingButton;
    // Level 10000010.0 renders above SpringBoard, banners, apps, and fullscreen games
    self.window.windowLevel = 10000010.0;
    self.window.hidden = NO;
    [self.window makeKeyAndVisible];

    // Register global window context with SpringBoard Accessibility Hosting Service
    Class hostCls = objc_getClass("SBSAccessibilityWindowHostingController");
    if (hostCls) {
        _windowHost = [[hostCls alloc] init];
        unsigned int contextID = [self.window _contextId];
        double level = self.window.windowLevel;

        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:"v@:Id"];
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        [inv setTarget:_windowHost];
        [inv setSelector:NSSelectorFromString(@"registerWindowWithContextID:atLevel:")];
        [inv setArgument:&contextID atIndex:2];
        [inv setArgument:&level atIndex:3];
        [inv invoke];
    }

    return YES;
}

@end
