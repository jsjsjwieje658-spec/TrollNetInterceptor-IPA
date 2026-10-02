//
//  UITouch-KIFAdditions (ported from TrollSpeed sources/KIF — Square KIF, MIT license)
//

#ifndef UITouchKIFAdditions_h
#define UITouchKIFAdditions_h

#import <UIKit/UIKit.h>

@interface UITouch (KIFAdditions)
- (instancetype)initAtPoint:(CGPoint)point
                   inWindow:(UIWindow *)window
                     onView:(UIView *)view;
- (instancetype)initTouch;
- (void)setLocationInWindow:(CGPoint)location;
- (void)setPhaseAndUpdateTimestamp:(UITouchPhase)phase;
@end

#endif /* UITouchKIFAdditions_h */
