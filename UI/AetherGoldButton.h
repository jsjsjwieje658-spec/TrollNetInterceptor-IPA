//
//  AetherGoldButton.h
//  AetherNet — Crash-proof gold primary button
//
//  Replaces UIButton entirely: UIButtonLegacyVisualProvider's title KVO crashes
//  when titles mutate while the button is in a layout pass (seen on iOS 16.7
//  with hooking frameworks present). A plain UIControl + UILabel has no legacy
//  visual provider, so that crash path cannot occur.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface AetherGoldButton : UIControl
@property (nonatomic, readonly, strong) UILabel *buttonLabel;
- (instancetype)initWithTitle:(NSString *)title;
- (void)applySecondaryStyle;
@end

NS_ASSUME_NONNULL_END
