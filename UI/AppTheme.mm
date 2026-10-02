//
//  AppTheme.mm
//  AetherNet — Obsidian & Champagne Luxury Design System
//

#import "AppTheme.h"
#import <QuartzCore/QuartzCore.h>

// Applies luxury wide letter-spacing to section headers
static void ApplyLetterSpacing(UILabel *label, CGFloat spacing) {
    NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:label.text ?: @""];
    [attr addAttribute:NSKernAttributeName value:@(spacing) range:NSMakeRange(0, attr.length)];
    label.attributedText = attr;
}

static UIImage *CircleThumbImage(CGFloat diameter) {
    UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
    fmt.opaque = NO;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(diameter, diameter) format:fmt];
    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *rctx) {
        CGContextRef ctx = rctx.CGContext;
        // Soft drop shadow
        CGContextSetShadowWithColor(ctx, CGSizeMake(0, 1.5), 3.0, [[UIColor colorWithWhite:0 alpha:0.45] CGColor]);
        CGContextSetFillColorWithColor(ctx, [AppTheme colorTextPrimary].CGColor);
        CGContextFillEllipseInRect(ctx, CGRectMake(1, 1, diameter - 2, diameter - 2));
    }];
}

@implementation AppTheme

#pragma mark - Palette

+ (UIColor *)colorObsidian      { return [UIColor colorWithRed:0.043 green:0.047 blue:0.055 alpha:1.0]; }
+ (UIColor *)colorElevated      { return [UIColor colorWithRed:0.075 green:0.082 blue:0.098 alpha:1.0]; }
+ (UIColor *)colorCardBorder    { return [UIColor colorWithWhite:1.0 alpha:0.085]; }
+ (UIColor *)colorTextPrimary   { return [UIColor colorWithRed:0.957 green:0.949 blue:0.929 alpha:1.0]; }
+ (UIColor *)colorTextSecondary { return [UIColor colorWithWhite:1.0 alpha:0.52]; }
+ (UIColor *)colorGold          { return [UIColor colorWithRed:0.906 green:0.769 blue:0.478 alpha:1.0]; }
+ (UIColor *)colorGoldMuted     { return [UIColor colorWithRed:0.71 green:0.63 blue:0.47 alpha:1.0]; }
+ (UIColor *)colorActiveGreen   { return [UIColor colorWithRed:0.40 green:0.86 blue:0.62 alpha:1.0]; }
+ (UIColor *)colorWarnRed       { return [UIColor colorWithRed:0.94 green:0.40 blue:0.40 alpha:1.0]; }
+ (UIColor *)colorUDPBlue       { return [UIColor colorWithRed:0.42 green:0.66 blue:0.96 alpha:1.0]; }
+ (UIColor *)colorTCPTeal       { return [UIColor colorWithRed:0.30 green:0.80 blue:0.76 alpha:1.0]; }

#pragma mark - Fonts

+ (UIFont *)displayFont:(CGFloat)size {
    return [UIFont systemFontOfSize:size weight:UIFontWeightBold];
}

+ (UIFont *)bodyFont:(CGFloat)size {
    return [UIFont systemFontOfSize:size];
}

+ (UIFont *)monoFont:(CGFloat)size {
    return [UIFont monospacedDigitSystemFontOfSize:size weight:UIFontWeightMedium];
}

#pragma mark - Components

+ (UIView *)cardContainerView {
    UIView *card = [[UIView alloc] init];
    card.backgroundColor = [self colorElevated];
    card.layer.cornerRadius = 18.0;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor = [self colorCardBorder].CGColor;
    card.layer.shadowColor = [UIColor blackColor].CGColor;
    card.layer.shadowOpacity = 0.35;
    card.layer.shadowOffset = CGSizeMake(0, 8);
    card.layer.shadowRadius = 18.0;
    return card;
}

+ (void)stylePrimaryButton:(UIButton *)button title:(NSString *)title {
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:[UIColor colorWithRed:0.08 green:0.07 blue:0.05 alpha:1.0] forState:UIControlStateNormal];
    [button setTitleColor:[UIColor colorWithWhite:0.1 alpha:0.55] forState:UIControlStateHighlighted];
    button.titleLabel.font = [self displayFont:15.0];

    CAGradientLayer *gloss = [CAGradientLayer layer];
    gloss.colors = @[
        (id)[self colorGold].CGColor,
        (id)[UIColor colorWithRed:0.82 green:0.66 blue:0.38 alpha:1.0].CGColor
    ];
    gloss.startPoint = CGPointMake(0, 0.5);
    gloss.endPoint = CGPointMake(1, 0.5);
    gloss.cornerRadius = 14.0;
    gloss.name = @"aetherPrimaryGloss";
    [button.layer insertSublayer:gloss atIndex:0];

    button.layer.shadowColor = [self colorGold].CGColor;
    button.layer.shadowOpacity = 0.30;
    button.layer.shadowRadius = 12.0;
    button.layer.shadowOffset = CGSizeMake(0, 4);
}

+ (void)styleSecondaryButton:(UIButton *)button title:(NSString *)title {
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:[self colorGoldMuted] forState:UIControlStateNormal];
    [button setTitleColor:[UIColor colorWithWhite:1 alpha:0.35] forState:UIControlStateHighlighted];
    button.titleLabel.font = [self displayFont:14.0];
    button.backgroundColor = [self colorElevated];
    button.layer.cornerRadius = 14.0;
    button.layer.borderWidth = 1.0;
    button.layer.borderColor = [[self colorGoldMuted] colorWithAlphaComponent:0.30].CGColor;
}

+ (void)styleSegmentedControl:(UISegmentedControl *)segment {
    segment.backgroundColor = [self colorObsidian];
    segment.selectedSegmentTintColor = [self colorGold];
    segment.layer.cornerRadius = 10.0;
    segment.layer.borderWidth = 1.0;
    segment.layer.borderColor = [self colorCardBorder].CGColor;

    NSDictionary *normalAttr = @{
        NSFontAttributeName: [self displayFont:12.5],
        NSForegroundColorAttributeName: [self colorTextSecondary]
    };
    NSDictionary *selectedAttr = @{
        NSFontAttributeName: [self displayFont:12.5],
        NSForegroundColorAttributeName: [UIColor colorWithRed:0.08 green:0.07 blue:0.05 alpha:1.0]
    };
    [segment setTitleTextAttributes:normalAttr forState:UIControlStateNormal];
    [segment setTitleTextAttributes:selectedAttr forState:UIControlStateSelected];
}

+ (void)styleSlider:(UISlider *)slider {
    slider.minimumTrackTintColor = [self colorGold];
    slider.maximumTrackTintColor = [UIColor colorWithWhite:1.0 alpha:0.12];
    UIImage *thumb = CircleThumbImage(22.0);
    [slider setThumbImage:thumb forState:UIControlStateNormal];
    [slider setThumbImage:thumb forState:UIControlStateHighlighted];
}

+ (UILabel *)titleLabelWithText:(NSString *)text {
    UILabel *label = [[UILabel alloc] init];
    label.text = text;
    label.font = [self displayFont:16.0];
    label.textColor = [self colorTextPrimary];
    return label;
}

+ (UILabel *)valueLabelWithText:(NSString *)text mono:(BOOL)mono {
    UILabel *label = [[UILabel alloc] init];
    label.text = text;
    label.font = mono ? [self monoFont:13.0] : [self bodyFont:13.5];
    label.textColor = [self colorTextSecondary];
    return label;
}

+ (UILabel *)sectionHeaderWithText:(NSString *)text {
    UILabel *label = [[UILabel alloc] init];
    label.font = [self displayFont:11.5];
    label.text = text.uppercaseString;
    label.textColor = [self colorGoldMuted];
    ApplyLetterSpacing(label, 1.6);
    return label;
}

+ (CAGradientLayer *)brandGradientLayer {
    CAGradientLayer *gradient = [CAGradientLayer layer];
    gradient.type = kCAGradientLayerAxial;
    gradient.colors = @[
        (id)[UIColor colorWithRed:0.031 green:0.034 blue:0.041 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.070 green:0.078 blue:0.096 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.038 green:0.040 blue:0.048 alpha:1.0].CGColor
    ];
    gradient.locations = @[@0.0, @0.55, @1.0];
    return gradient;
}

@end
