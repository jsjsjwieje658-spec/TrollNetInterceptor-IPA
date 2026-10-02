//
//  HUDMainWindow.mm
//  AetherNet — System-Wide Passthrough Overlay Window
//  Uses assistivetouchd / SpringBoard accessibility window hosting SPI
//

#import "HUDMainWindow.h"
#import "../headers/PrivateSystemSPI.h"

@implementation AetherHUDMainWindow

+ (BOOL)_isSystemWindow {
    return YES;
}

- (BOOL)_isWindowServerHostingManaged {
    return NO;
}

- (BOOL)_isSecure {
    return YES;
}

- (BOOL)_shouldCreateContextAsSecure {
    return YES;
}

// Critical: Only intercept touches that land directly inside the circular Floating Button.
// All other screen touches pass straight through to the foreground app or game!
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    if (!self.interactiveFloatingButton || self.interactiveFloatingButton.hidden) {
        return nil;
    }
    CGPoint buttonPoint = [self convertPoint:point toView:self.interactiveFloatingButton];
    if ([self.interactiveFloatingButton pointInside:buttonPoint withEvent:event]) {
        return [self.interactiveFloatingButton hitTest:buttonPoint withEvent:event];
    }
    return nil;
}

@end
