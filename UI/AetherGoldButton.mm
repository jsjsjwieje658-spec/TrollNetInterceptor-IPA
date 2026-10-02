//
//  AetherGoldButton.mm
//  AetherNet — Crash-proof gold primary button
//

#import "AetherGoldButton.h"
#import "AppTheme.h"

@implementation AetherGoldButton {
    CAGradientLayer *_gloss;
}

- (instancetype)initWithTitle:(NSString *)title
{
    self = [super init];
    if (self) {
        _buttonLabel = [[UILabel alloc] init];
        _buttonLabel.text = title;
        _buttonLabel.font = [AppTheme displayFont:15.0];
        _buttonLabel.textColor = [UIColor colorWithRed:0.08 green:0.07 blue:0.05 alpha:1.0];
        _buttonLabel.textAlignment = NSTextAlignmentCenter;
        _buttonLabel.userInteractionEnabled = NO;
        _buttonLabel.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_buttonLabel];

        [NSLayoutConstraint activateConstraints:@[
            [_buttonLabel.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_buttonLabel.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_buttonLabel.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.leadingAnchor constant:12],
            [_buttonLabel.trailingAnchor constraintLessThanOrEqualToAnchor:self.trailingAnchor constant:-12],
        ]];

        _gloss = [CAGradientLayer layer];
        _gloss.colors = @[
            (id)[AppTheme colorGold].CGColor,
            (id)[UIColor colorWithRed:0.82 green:0.66 blue:0.38 alpha:1.0].CGColor
        ];
        _gloss.startPoint = CGPointMake(0, 0.5);
        _gloss.endPoint   = CGPointMake(1, 0.5);
        _gloss.cornerRadius = 14.0;
        [self.layer insertSublayer:_gloss atIndex:0];

        self.layer.cornerRadius = 14.0;
        // Hard guarantee: nothing this control draws can ever paint outside its
        // bounds (fixes the "button stretches past the card" rendering glitch).
        self.layer.masksToBounds = YES;
        self.layer.shadowColor = [AppTheme colorGold].CGColor;
        self.layer.shadowOpacity = 0.30;
        self.layer.shadowRadius = 12.0;
        self.layer.shadowOffset = CGSizeMake(0, 4);
    }
    return self;
}

- (void)applySecondaryStyle {
    _gloss.colors = @[
        (id)[AppTheme colorElevated].CGColor,
        (id)[AppTheme colorElevated].CGColor
    ];
    _buttonLabel.textColor = [AppTheme colorGoldMuted];
    self.layer.borderWidth = 1.0;
    self.layer.borderColor = [[AppTheme colorGoldMuted] colorWithAlphaComponent:0.30].CGColor;
    self.layer.shadowOpacity = 0.0;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    _gloss.frame = self.bounds;
}

- (BOOL)beginTrackingWithTouch:(UITouch *)touch withEvent:(UIEvent *)event {
    BOOL tracking = [super beginTrackingWithTouch:touch withEvent:event];
    self.alpha = 0.82;
    return tracking;
}

- (void)endTrackingWithTouch:(UITouch *)touch withEvent:(UIEvent *)event {
    [super endTrackingWithTouch:touch withEvent:event];
    self.alpha = 1.0;
    // NOTE: UIControl's native touch pipeline already dispatches
    // TouchUpInside right after endTracking for any UIControl subclass.
    // Do NOT sendActionsForControlEvents here as well — 3.1.x fired every
    // action twice (proof: log showed START followed by STOP 11ms later,
    // and Create spawned TWO daemons per tap).
}

- (void)cancelTrackingWithEvent:(UIEvent *)event {
    [super cancelTrackingWithEvent:event];
    self.alpha = 1.0;
}

@end
