//
//  TSEventFetcher.h (ported from TrollSpeed — Lessica/82flex, MIT license)
//  Delivers synthesized UITouches into UIKit's event pipeline so that
//  gesture recognizers work inside a plugin-mode HUD process.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface TSEventFetcher : NSObject
+ (NSInteger)receiveAXEventID:(NSInteger)pointId
           atGlobalCoordinate:(CGPoint)point
               withTouchPhase:(UITouchPhase)phase
                     inWindow:(UIWindow *)window
                       onView:(UIView *)view;
@end

NS_ASSUME_NONNULL_END
