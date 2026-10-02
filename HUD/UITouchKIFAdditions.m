//
//  UITouch-KIFAdditions (ported from TrollSpeed sources/KIF — Square KIF, MIT license)
//  Defensive adjustments: plugin-mode UIApplication has no UIWindowScene,
//  so initTouch() falls back to keyWindow / last window.
//

#import "UITouchKIFAdditions.h"
#import "IOHIDEventKIF.h"
#import "../headers/AetherTouchPrivate.h"
#import <objc/runtime.h>

@implementation UITouch (KIFAdditions)

- (instancetype)initAtPoint:(CGPoint)point
                   inWindow:(UIWindow *)window
                     onView:(UIView *)view
{
    self = [super init];
    if (self == nil) return nil;

    // Create a fake tap touch
    [self setWindow:window]; // Wipes out some values. Needs to be first.
    [self _setLocationInWindow:point resetPrevious:YES];

    UIView *hitTestView = view;
    [self setView:hitTestView];
    [self setPhase:UITouchPhaseBegan];

    BOOL isMacLike = [[NSProcessInfo processInfo] isiOSAppOnMac] ||
                     [[NSProcessInfo processInfo] isMacCatalystApp];
    if (!isMacLike) {
        [self _setIsTapToClick:NO];
    } else {
        [self _setIsFirstTouchForView:YES];
        [self setIsTap:NO];
    }

    [self setTimestamp:[[NSProcessInfo processInfo] systemUptime]];

    if ([self respondsToSelector:@selector(setGestureView:)])
        [self setGestureView:hitTestView];

    [self kif_setHidEvent];
    return self;
}

- (instancetype)initTouch
{
    self = [super init];
    if (self == nil) return nil;

    UIWindow *window = nil;
    NSArray *scenes = [[[UIApplication sharedApplication] connectedScenes] allObjects];
    for (UIScene *scene in scenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            window = [(UIWindowScene *)scene windows].lastObject;
            break;
        }
    }
    if (!window) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        window = [UIApplication sharedApplication].keyWindow ?: [UIApplication sharedApplication].windows.lastObject;
#pragma clang diagnostic pop
    }
    CGPoint point = CGPointMake(0, 0);

    [self setWindow:window];
    [self _setLocationInWindow:point resetPrevious:YES];

    UIView *hitTestView = window ? [window hitTest:point withEvent:nil] : nil;
    [self setView:hitTestView];
    [self setPhase:UITouchPhaseEnded];

    BOOL isMacLike = [[NSProcessInfo processInfo] isiOSAppOnMac] ||
                     [[NSProcessInfo processInfo] isMacCatalystApp];
    if (!isMacLike) {
        [self _setIsTapToClick:NO];
    } else {
        [self _setIsFirstTouchForView:YES];
        [self setIsTap:NO];
    }

    [self setTimestamp:[[NSProcessInfo processInfo] systemUptime]];

    if ([self respondsToSelector:@selector(setGestureView:)])
        [self setGestureView:hitTestView];

    [self kif_setHidEvent];
    return self;
}

- (void)setLocationInWindow:(CGPoint)location
{
    [self setTimestamp:[[NSProcessInfo processInfo] systemUptime]];
    [self _setLocationInWindow:location resetPrevious:NO];
}

- (void)setPhaseAndUpdateTimestamp:(UITouchPhase)phase
{
    [self setTimestamp:[[NSProcessInfo processInfo] systemUptime]];
    [self setPhase:phase];
}

- (void)kif_setHidEvent
{
    IOHIDEventRef event = kif_IOHIDEventWithTouches(@[ self ]);
    [self _setHidEvent:event];
    CFRelease(event);
}

@end
