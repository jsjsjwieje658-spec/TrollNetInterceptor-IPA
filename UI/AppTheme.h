//
//  AppTheme.h
//  AetherNet — Obsidian & Champagne Luxury Design System
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppTheme : NSObject

// Palette
+ (UIColor *)colorObsidian;        // Deep charcoal-black background
+ (UIColor *)colorElevated;        // Card surface (elevated obsidian)
+ (UIColor *)colorCardBorder;      // Hairline champagne border
+ (UIColor *)colorTextPrimary;     // Ivory white
+ (UIColor *)colorTextSecondary;   // Muted silver-grey
+ (UIColor *)colorGold;            // Champagne gold accent
+ (UIColor *)colorGoldMuted;       // Desaturated gold
+ (UIColor *)colorActiveGreen;     // Live telemetry green
+ (UIColor *)colorWarnRed;         // Dropped / error red
+ (UIColor *)colorUDPBlue;         // UDP flow blue
+ (UIColor *)colorTCPTeal;         // TCP stream teal

// Components
+ (UIView *)cardContainerView;                                  // Rounded 18pt frosted card
+ (void)stylePrimaryButton:(UIButton *)button title:(NSString *)title;
+ (void)styleSecondaryButton:(UIButton *)button title:(NSString *)title;
+ (void)styleSegmentedControl:(UISegmentedControl *)segment;
+ (void)styleSlider:(UISlider *)slider;
+ (UILabel *)titleLabelWithText:(NSString *)text;
+ (UILabel *)valueLabelWithText:(NSString *)text mono:(BOOL)mono;
+ (UILabel *)sectionHeaderWithText:(NSString *)text;

+ (CAGradientLayer *)brandGradientLayer;                        // Background mesh gradient

// Fonts
+ (UIFont *)displayFont:(CGFloat)size;
+ (UIFont *)bodyFont:(CGFloat)size;
+ (UIFont *)monoFont:(CGFloat)size;

@end

NS_ASSUME_NONNULL_END
