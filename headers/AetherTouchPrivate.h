//
//  AetherTouchPrivate.h
//  AetherNet — UITouch / UIEvent private SPI declarations
//  (selectors verified on iOS 14 – 17, same set TrollSpeed/KIF rely on)
//

#ifndef AetherTouchPrivate_h
#define AetherTouchPrivate_h

#import <UIKit/UIKit.h>

@interface UITouch (AetherPrivate)
- (void)setWindow:(UIWindow *)window;
- (void)setView:(UIView *)view;
- (void)setPhase:(UITouchPhase)phase;
- (void)setTimestamp:(NSTimeInterval)timestamp;
- (void)setIsTap:(BOOL)isTap;
- (void)_setLocationInWindow:(CGPoint)location resetPrevious:(BOOL)reset;
- (void)_setIsTapToClick:(BOOL)isTapToClick;
- (void)_setIsFirstTouchForView:(BOOL)first;
- (void)setGestureView:(UIView *)view;
- (void)_setHidEvent:(void *)event;
@end

@interface UIEvent (AetherPrivate)
- (UIEvent *)_touchesEvent; // on UIApplication actually — kept for reference
- (void)_clearTouches;
- (void)_addTouch:(UITouch *)touch forDelayedDelivery:(BOOL)delayed;
@end

@interface UIApplication (AetherTouchPrivate)
- (UIEvent *)_touchesEvent;
@end

#endif /* AetherTouchPrivate_h */
