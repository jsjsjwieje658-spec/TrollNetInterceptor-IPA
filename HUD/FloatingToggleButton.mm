//
//  FloatingToggleButton.mm
//  AetherNet — Luxury Circular Floating Button Over All Processes
//
//  Visual Specification:
//    - Circular button with AetherNet orbital crest logo ring
//    - OFF state (Standby): Triangle (▶) centered inside the circle
//    - ON state (Intercepting TCP/UDP): Two parallel vertical bars (⏸) centered inside the circle
//    - Dynamically resizable (40pt - 88pt) via Settings Tab
//

#import "FloatingToggleButton.h"
#import "../Core/AetherLog.h"
#import <QuartzCore/QuartzCore.h>
#include <math.h>
#include <notify.h>
#include "../headers/AetherNetShared.h"
#import "../Core/ProcessManager.h"

@implementation AetherFloatingToggleButton {
    UIVisualEffectView *_blurView;
    CAGradientLayer *_metallicRimLayer;
    CAShapeLayer *_logoOrbitalRingLayer;
    CAShapeLayer *_activePulseRingLayer;
    CAShapeLayer *_playTriangleLayer;
    CAShapeLayer *_pauseParallelBarsLayer;
    UILabel *_heldBadgeLabel;

    CGPoint _dragStartCenter;
    BOOL _isCurrentlyActive;
    BOOL _isDragging;
    CGFloat _currentDiameter;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if (self = [super initWithFrame:frame]) {
        _currentDiameter = frame.size.width > 0 ? frame.size.width : 58.0;
        [self setupLuxurySublayers];
        [self setupGestureRecognizers];
        [self syncWithSharedStateAnimated:NO];
    }
    return self;
}

- (void)setupLuxurySublayers {
    self.backgroundColor = [UIColor clearColor];
    self.layer.shadowColor = [UIColor blackColor].CGColor;
    self.layer.shadowOpacity = 0.48f;
    self.layer.shadowRadius = 14.0f;
    self.layer.shadowOffset = CGSizeMake(0, 6);

    // 1. Frosted Obsidian Glass Core
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterialDark];
    _blurView = [[UIVisualEffectView alloc] initWithEffect:blur];
    _blurView.userInteractionEnabled = NO;
    _blurView.clipsToBounds = YES;
    _blurView.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.08 alpha:0.78];
    [self addSubview:_blurView];

    // 2. Brushed Champagne Gold / Titanium Rim
    _metallicRimLayer = [CAGradientLayer layer];
    _metallicRimLayer.colors = @[
        (id)[UIColor colorWithRed:0.86 green:0.76 blue:0.56 alpha:0.65].CGColor,
        (id)[UIColor colorWithRed:0.22 green:0.24 blue:0.28 alpha:0.25].CGColor,
        (id)[UIColor colorWithRed:0.86 green:0.76 blue:0.56 alpha:0.45].CGColor
    ];
    _metallicRimLayer.startPoint = CGPointMake(0.0, 0.0);
    _metallicRimLayer.endPoint = CGPointMake(1.0, 1.0);
    [self.layer addSublayer:_metallicRimLayer];

    // 3. AetherNet Segmented Logo Orbital Ring
    _logoOrbitalRingLayer = [CAShapeLayer layer];
    _logoOrbitalRingLayer.fillColor = [UIColor clearColor].CGColor;
    _logoOrbitalRingLayer.strokeColor = [UIColor colorWithRed:0.85 green:0.74 blue:0.54 alpha:0.72].CGColor;
    _logoOrbitalRingLayer.lineWidth = 1.5;
    _logoOrbitalRingLayer.lineCap = kCALineCapRound;
    _logoOrbitalRingLayer.lineDashPattern = @[@10, @5, @3, @5];
    [self.layer addSublayer:_logoOrbitalRingLayer];

    // 4. Active Interception Pulse Ring (Visible when ⏸ is active)
    _activePulseRingLayer = [CAShapeLayer layer];
    _activePulseRingLayer.fillColor = [UIColor clearColor].CGColor;
    _activePulseRingLayer.strokeColor = [UIColor colorWithRed:0.92 green:0.68 blue:0.34 alpha:0.90].CGColor;
    _activePulseRingLayer.lineWidth = 2.0;
    _activePulseRingLayer.opacity = 0.0f;
    [self.layer addSublayer:_activePulseRingLayer];

    // 5. Center Icon A: Triangle (▶) when NOT intercepting
    _playTriangleLayer = [CAShapeLayer layer];
    _playTriangleLayer.fillColor = [UIColor colorWithRed:0.95 green:0.93 blue:0.89 alpha:0.96].CGColor;
    _playTriangleLayer.strokeColor = [UIColor colorWithRed:0.85 green:0.74 blue:0.54 alpha:0.60].CGColor;
    _playTriangleLayer.lineWidth = 1.0;
    _playTriangleLayer.lineJoin = kCALineJoinRound;
    [self.layer addSublayer:_playTriangleLayer];

    // 6. Center Icon B: Two Parallel Vertical Bars (⏸) when INTERCEPTING TCP/UDP
    _pauseParallelBarsLayer = [CAShapeLayer layer];
    _pauseParallelBarsLayer.fillColor = [UIColor colorWithRed:0.96 green:0.79 blue:0.47 alpha:1.0].CGColor;
    _pauseParallelBarsLayer.opacity = 0.0f;
    [self.layer addSublayer:_pauseParallelBarsLayer];

    // 7. Mini Pill Badge showing held packets count when active
    _heldBadgeLabel = [[UILabel alloc] init];
    _heldBadgeLabel.font = [UIFont monospacedDigitSystemFontOfSize:9.0 weight:UIFontWeightBold];
    _heldBadgeLabel.textColor = [UIColor colorWithRed:0.06 green:0.07 blue:0.09 alpha:1.0];
    _heldBadgeLabel.backgroundColor = [UIColor colorWithRed:0.91 green:0.76 blue:0.48 alpha:1.0];
    _heldBadgeLabel.textAlignment = NSTextAlignmentCenter;
    _heldBadgeLabel.clipsToBounds = YES;
    _heldBadgeLabel.hidden = YES;
    [self addSubview:_heldBadgeLabel];

    [self updateGeometryForDiameter:_currentDiameter];
}

- (void)updateGeometryForDiameter:(CGFloat)diameter {
    _currentDiameter = MAX(40.0, MIN(88.0, diameter));
    CGRect bounds = CGRectMake(0, 0, _currentDiameter, _currentDiameter);
    self.bounds = bounds;

    CGFloat radius = _currentDiameter / 2.0;
    _blurView.frame = bounds;
    _blurView.layer.cornerRadius = radius;

    // Outer metallic border mask
    _metallicRimLayer.frame = bounds;
    _metallicRimLayer.cornerRadius = radius;
    CAShapeLayer *rimMask = [CAShapeLayer layer];
    rimMask.path = [UIBezierPath bezierPathWithOvalInRect:CGRectInset(bounds, 0.75, 0.75)].CGPath;
    rimMask.fillColor = [UIColor clearColor].CGColor;
    rimMask.strokeColor = [UIColor whiteColor].CGColor;
    rimMask.lineWidth = 1.5;
    _metallicRimLayer.mask = rimMask;

    // Inner logo orbital ring
    CGRect logoRingRect = CGRectInset(bounds, _currentDiameter * 0.12, _currentDiameter * 0.12);
    _logoOrbitalRingLayer.frame = bounds;
    _logoOrbitalRingLayer.path = [UIBezierPath bezierPathWithOvalInRect:logoRingRect].CGPath;

    _activePulseRingLayer.frame = bounds;
    _activePulseRingLayer.path = [UIBezierPath bezierPathWithOvalInRect:CGRectInset(bounds, 2.0, 2.0)].CGPath;

    // Center Play Triangle (▶) Path — optically centered inside circle
    CGFloat center = _currentDiameter / 2.0;
    CGFloat triRadius = _currentDiameter * 0.21;
    CGFloat opticalOffsetX = _currentDiameter * 0.03; // Slight right shift for visual balance

    UIBezierPath *triPath = [UIBezierPath bezierPath];
    [triPath moveToPoint:CGPointMake(center - triRadius * 0.72 + opticalOffsetX, center - triRadius * 0.88)];
    [triPath addLineToPoint:CGPointMake(center + triRadius * 0.96 + opticalOffsetX, center)];
    [triPath addLineToPoint:CGPointMake(center - triRadius * 0.72 + opticalOffsetX, center + triRadius * 0.88)];
    [triPath closePath];
    _playTriangleLayer.frame = bounds;
    _playTriangleLayer.path = triPath.CGPath;

    // Center Two Parallel Vertical Bars (⏸) Path — video pause style when active
    CGFloat barWidth = MAX(3.2, _currentDiameter * 0.078);
    CGFloat barHeight = _currentDiameter * 0.34;
    CGFloat barSpacing = _currentDiameter * 0.095;
    CGFloat barCorner = barWidth / 2.0;

    CGRect leftBarRect = CGRectMake(center - barSpacing / 2.0 - barWidth,
                                    center - barHeight / 2.0,
                                    barWidth,
                                    barHeight);
    CGRect rightBarRect = CGRectMake(center + barSpacing / 2.0,
                                     center - barHeight / 2.0,
                                     barWidth,
                                     barHeight);

    UIBezierPath *pausePath = [UIBezierPath bezierPathWithRoundedRect:leftBarRect cornerRadius:barCorner];
    [pausePath appendPath:[UIBezierPath bezierPathWithRoundedRect:rightBarRect cornerRadius:barCorner]];
    _pauseParallelBarsLayer.frame = bounds;
    _pauseParallelBarsLayer.path = pausePath.CGPath;

    // Badge position at top-right of the circle
    _heldBadgeLabel.frame = CGRectMake(_currentDiameter - 22.0, -2.0, 24.0, 14.0);
    _heldBadgeLabel.layer.cornerRadius = 7.0;
}

- (void)setupGestureRecognizers {
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleButtonTap:)];
    [self addGestureRecognizer:tap];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleButtonPan:)];
    [self addGestureRecognizer:pan];
}

- (void)handleButtonTap:(UITapGestureRecognizer *)recognizer {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    bool nextState = !aether_atomic_load(&state->interceptionActive);
    AetherLog(@"floating button TAP -> interception %s", nextState ? "ON" : "OFF");

    // Remember that THIS gesture was consumed here: the same physical tap is
    // also delivered to the app underneath, whose "Remove Floating Button" sit
    // right below the overlay on some layouts (that is how the button used to
    // disappear a few seconds after starting a capture).
    CGPoint tapPoint = [recognizer locationInView:nil];
    aether_atomic_store(&state->hudTapConsumedMs, (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0));
    aether_atomic_store(&state->hudTapConsumedX, (int32_t)tapPoint.x);
    aether_atomic_store(&state->hudTapConsumedY, (int32_t)tapPoint.y);

    [[AetherProcessManager sharedManager] setInterceptionActive:nextState];

    if (aether_atomic_load(&state->floatingHapticEnabled)) {
        UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:
            nextState ? UIImpactFeedbackStyleHeavy : UIImpactFeedbackStyleMedium];
        [feedback impactOccurred];
    }

    // Subtle press scale animation
    [UIView animateWithDuration:0.12 animations:^{
        self.transform = CGAffineTransformMakeScale(0.91, 0.91);
    } completion:^(BOOL finished) {
        [UIView animateWithDuration:0.22
                              delay:0
             usingSpringWithDamping:0.55
              initialSpringVelocity:0.8
                            options:UIViewAnimationOptionCurveEaseOut
                         animations:^{
            self.transform = CGAffineTransformIdentity;
        } completion:nil];
    }];

    [self syncWithSharedStateAnimated:YES];
}

- (void)handleButtonPan:(UIPanGestureRecognizer *)recognizer {
    AetherSharedState *state = AetherGetSharedState();
    if (state && aether_atomic_load(&state->floatingLockPosition)) {
        return; // Position locked in Settings tab
    }

    UIView *superview = self.superview;
    if (!superview) return;

    if (recognizer.state == UIGestureRecognizerStateBegan) {
        _dragStartCenter = self.center;
        _isDragging = YES;
    } else if (recognizer.state == UIGestureRecognizerStateChanged) {
        CGPoint translation = [recognizer translationInView:superview];
        CGFloat half = _currentDiameter / 2.0 + 8.0;
        CGFloat newX = MAX(half, MIN(superview.bounds.size.width - half, _dragStartCenter.x + translation.x));
        CGFloat newY = MAX(half + 44.0, MIN(superview.bounds.size.height - half - 34.0, _dragStartCenter.y + translation.y));
        self.center = CGPointMake(newX, newY);
    } else if (recognizer.state == UIGestureRecognizerStateEnded ||
               recognizer.state == UIGestureRecognizerStateCancelled) {
        _isDragging = NO;
        CGPoint finalCenter = self.center;
        AetherLog(@"floating button DRAG -> pos %.0f,%.0f", finalCenter.x, finalCenter.y);
        if (!state || aether_atomic_load(&state->floatingEdgeSnap)) {
            CGFloat margin = _currentDiameter / 2.0 + 12.0;
            CGFloat screenW = superview.bounds.size.width;
            finalCenter.x = (finalCenter.x < screenW / 2.0) ? margin : (screenW - margin);
            [UIView animateWithDuration:0.28
                                  delay:0
                 usingSpringWithDamping:0.72
                  initialSpringVelocity:0.6
                                options:UIViewAnimationOptionCurveEaseOut
                             animations:^{
                self.center = finalCenter;
            } completion:nil];
        }
        if (state) {
            aether_atomic_store(&state->floatingPosX, (float)finalCenter.x);
            aether_atomic_store(&state->floatingPosY, (float)finalCenter.y);
        }
    }
}

- (void)syncWithSharedStateAnimated:(BOOL)animated {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    CGFloat targetSize = (CGFloat)aether_atomic_load(&state->floatingButtonSize);
    CGFloat targetOpacity = (CGFloat)aether_atomic_load(&state->floatingButtonOpacity);
    BOOL isActive = aether_atomic_load(&state->interceptionActive);
    uint64_t heldCount = aether_atomic_load(&state->heldPacketsCount);

    if (fabs(targetSize - _currentDiameter) > 0.5) {
        CGPoint oldCenter = self.center;
        [self updateGeometryForDiameter:targetSize];
        self.center = oldCenter;
    }

    self.alpha = MAX(0.35, MIN(1.0, targetOpacity));
    _isCurrentlyActive = isActive;

    // Position sync from shared memory (app sliders / remote updates).
    // Skip while the finger is on the button, and ignore unset/garbage values.
    if (!_isDragging) {
        CGFloat px = (CGFloat)aether_atomic_load(&state->floatingPosX);
        CGFloat py = (CGFloat)aether_atomic_load(&state->floatingPosY);
        UIView *sv = self.superview;
        if (sv && px > 8.0 && py > 8.0 &&
            px < sv.bounds.size.width - 8.0 && py < sv.bounds.size.height - 8.0) {
            CGPoint target = CGPointMake(px, py);
            if (!CGPointEqualToPoint(target, self.center)) {
                if (animated) {
                    [UIView animateWithDuration:0.18 animations:^{ self.center = target; }];
                } else {
                    self.center = target;
                }
            }
        }
    }

    // Toggle between Triangle (▶) when OFF and Two Parallel Bars (⏸) when ON
    [CATransaction begin];
    [CATransaction setAnimationDuration:animated ? 0.18 : 0.0];
    _playTriangleLayer.opacity = isActive ? 0.0f : 1.0f;
    _pauseParallelBarsLayer.opacity = isActive ? 1.0f : 0.0f;
    _activePulseRingLayer.opacity = isActive ? 1.0f : 0.0f;
    _logoOrbitalRingLayer.strokeColor = isActive
        ? [UIColor colorWithRed:0.96 green:0.79 blue:0.47 alpha:0.95].CGColor
        : [UIColor colorWithRed:0.85 green:0.74 blue:0.54 alpha:0.60].CGColor;
    [CATransaction commit];

    if (isActive) {
        if (![_logoOrbitalRingLayer animationForKey:@"orbitalSpin"]) {
            CABasicAnimation *spin = [CABasicAnimation animationWithKeyPath:@"transform.rotation.z"];
            spin.fromValue = @(0);
            spin.toValue = @(M_PI * 2.0);
            spin.duration = 8.0;
            spin.repeatCount = HUGE_VALF;
            [_logoOrbitalRingLayer addAnimation:spin forKey:@"orbitalSpin"];
        }
        if (heldCount > 0) {
            _heldBadgeLabel.hidden = NO;
            _heldBadgeLabel.text = heldCount > 99 ? @"99+" : [NSString stringWithFormat:@"%llu", heldCount];
        } else {
            _heldBadgeLabel.hidden = YES;
        }
    } else {
        [_logoOrbitalRingLayer removeAnimationForKey:@"orbitalSpin"];
        _heldBadgeLabel.hidden = YES;
    }
}

@end
