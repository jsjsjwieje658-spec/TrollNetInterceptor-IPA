//
//  FloatingToggleButton.h
//  AetherNet — Circular Floating HUD Button with Logo Ring & Play (▶) / Pause (⏸) Morph
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface AetherFloatingToggleButton : UIView

/// Updates button diameter (40pt - 88pt), opacity, and Play/Pause icon state from shared memory
- (void)syncWithSharedStateAnimated:(BOOL)animated;

@end

NS_ASSUME_NONNULL_END
