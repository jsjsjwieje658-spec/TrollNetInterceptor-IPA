//
//  SettingsViewController.mm
//  AetherNet — Tab 2: Settings
//
//  Sections:
//   1. INTERCEPTION RULES
//        - Direction:  Both ▸ Download only ▸ Upload only
//        - Protocol:   TCP + UDP ▸ UDP only ▸ TCP only
//        - Mode:       Hold Queue ▸ Drop ▸ Delay+Jitter ▸ Tamper ▸ Observe
//                      (Observe = capture only: nothing is held, nothing is
//                       frozen — the target keeps running normally)
//        - Master capture ratio slider (0-100 %)
//        - Download hold ratio & Upload hold ratio sliders
//   2. NETWORK STATE SIMULATION
//        - Presets: Normal · Ghost/Freeze · Lag Spike · Degraded 3G · TCP Reset
//        - Latency (ms) · Jitter (ms) · Bandwidth cap (kbps) · Duplicate %
//        - Safety auto-flush of held packets
//   3. FLOATING BUTTON
//        - Diameter slider (40 - 88 pt)
//        - Opacity slider (35 - 100 %)
//        - Edge snap / position lock / haptic feedback switches
//

#import "SettingsViewController.h"
#import "AppTheme.h"
#import "../Core/L4Engine/AetherShaper.h"
#import "../Core/ProcessManager.h"
#import "../headers/AetherNetShared.h"
#include <math.h>
#include <notify.h>

@interface SettingsViewController () <UIScrollViewDelegate>
@property (nonatomic, strong) UIScrollView *scrollView;

// Capture rule controls
@property (nonatomic, strong) UISegmentedControl *directionSegment;
@property (nonatomic, strong) UISegmentedControl *protocolSegment;
@property (nonatomic, strong) UISegmentedControl *modeSegment;
@property (nonatomic, strong) UISlider *masterRatioSlider;
@property (nonatomic, strong) UILabel *masterRatioValue;
@property (nonatomic, strong) UISlider *downloadSlider;
@property (nonatomic, strong) UILabel *downloadValue;
@property (nonatomic, strong) UISlider *uploadSlider;
@property (nonatomic, strong) UILabel *uploadValue;

// Network simulation controls
@property (nonatomic, strong) UISegmentedControl *presetSegment;
@property (nonatomic, strong) UISlider *latencySlider;
@property (nonatomic, strong) UILabel *latencyValue;
@property (nonatomic, strong) UISlider *jitterSlider;
@property (nonatomic, strong) UILabel *jitterValue;
@property (nonatomic, strong) UISlider *bandwidthSlider;
@property (nonatomic, strong) UILabel *bandwidthValue;
@property (nonatomic, strong) UISlider *duplicateSlider;
@property (nonatomic, strong) UILabel *duplicateValue;
@property (nonatomic, strong) UISegmentedControl *autoFlushSegment;

// Floating button controls
@property (nonatomic, strong) UISlider *sizeSlider;
@property (nonatomic, strong) UILabel *sizeValue;
@property (nonatomic, strong) UISlider *opacitySlider;
@property (nonatomic, strong) UILabel *opacityValue;
@property (nonatomic, strong) UISwitch *snapSwitch;
@property (nonatomic, strong) UISwitch *lockSwitch;
@property (nonatomic, strong) UISwitch *hapticSwitch;
@property (nonatomic, strong) UISwitch *freezeSwitch;
@property (nonatomic, strong) UILabel  *modeAvailNote;
@property (nonatomic, strong) UISlider *lagSpikeSlider;
@property (nonatomic, strong) UILabel  *lagSpikeValue;
@property (nonatomic, strong) UISlider *lagCycleSlider;
@property (nonatomic, strong) UILabel  *lagCycleValue;
@property (nonatomic, strong) UISlider *xSlider;
@property (nonatomic, strong) UILabel *xValue;
@property (nonatomic, strong) UISlider *ySlider;
@property (nonatomic, strong) UILabel *yValue;
@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [AppTheme colorObsidian];
    self.title = @"Settings";
    [self buildUI];
    [self loadFromSharedState];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    for (CALayer *sub in self.view.layer.sublayers) {
        if ([sub isKindOfClass:[CAGradientLayer class]]) sub.frame = self.view.bounds;
    }
}

#pragma mark - UI Construction Helpers

- (UIView *)makeCardWithTitle:(NSString *)title into:(UIView **)outTitle {
    UIView *card = [AppTheme cardContainerView];
    UILabel *header = [AppTheme sectionHeaderWithText:title];
    [card addSubview:header];
    header.translatesAutoresizingMaskIntoConstraints = NO;
    [NSLayoutConstraint activateConstraints:@[
        [header.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
    ]];
    if (outTitle) *outTitle = header;
    return card;
}

- (UILabel *)rowTitle:(NSString *)text into:(UIView *)parent above:(UIView *)sibling constant:(CGFloat)c {
    UILabel *label = [AppTheme titleLabelWithText:text];
    label.font = [AppTheme displayFont:13.5];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [parent addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.topAnchor constraintEqualToAnchor:(sibling ? sibling.bottomAnchor : parent.topAnchor) constant:c],
        [label.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor constant:16],
    ]];
    return label;
}

- (UISegmentedControl *)makeSegmentWithItems:(NSArray *)items
                                      parent:(UIView *)parent
                                      above:(UIView *)sibling
                                    constant:(CGFloat)c
                                      action:(SEL)action {
    UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:items];
    [AppTheme styleSegmentedControl:seg];
    seg.translatesAutoresizingMaskIntoConstraints = NO;
    [seg addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    [parent addSubview:seg];
    [NSLayoutConstraint activateConstraints:@[
        [seg.topAnchor constraintEqualToAnchor:(sibling ? sibling.bottomAnchor : parent.topAnchor) constant:c],
        [seg.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor constant:16],
        [seg.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor constant:-16],
        [seg.heightAnchor constraintEqualToConstant:32],
    ]];
    return seg;
}

- (UISlider *)makeSliderRow:(NSString *)title
                    min:(double)minV
                    max:(double)maxV
                  parent:(UIView *)parent
                  above:(UIView *)sibling
               constant:(CGFloat)c
                 slider:(UISlider * __strong *)outSlider
                  value:(UILabel * __strong *)outValue
                 action:(SEL)action {
    UILabel *label = [AppTheme titleLabelWithText:title];
    label.font = [AppTheme displayFont:13.5];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [parent addSubview:label];

    UILabel *value = [AppTheme valueLabelWithText:@"" mono:YES];
    value.translatesAutoresizingMaskIntoConstraints = NO;
    [parent addSubview:value];

    UISlider *slider = [[UISlider alloc] init];
    slider.minimumValue = minV;
    slider.maximumValue = maxV;
    [AppTheme styleSlider:slider];
    slider.translatesAutoresizingMaskIntoConstraints = NO;
    [slider addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    [parent addSubview:slider];

    [NSLayoutConstraint activateConstraints:@[
        [label.topAnchor constraintEqualToAnchor:(sibling ? sibling.bottomAnchor : parent.topAnchor) constant:c],
        [label.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor constant:16],
        [value.centerYAnchor constraintEqualToAnchor:label.centerYAnchor],
        [value.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor constant:-16],
        [slider.topAnchor constraintEqualToAnchor:label.bottomAnchor constant:6],
        [slider.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor constant:16],
        [slider.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor constant:-16],
        [slider.heightAnchor constraintEqualToConstant:30],
    ]];
    *outSlider = slider;
    *outValue = value;
    return slider;
}

#pragma mark - Build

- (void)buildUI {
    CAGradientLayer *bg = [AppTheme brandGradientLayer];
    bg.frame = self.view.bounds;
    [self.view.layer insertSublayer:bg atIndex:0];

    self.scrollView = [[UIScrollView alloc] init];
    self.scrollView.alwaysBounceVertical = YES;
    self.scrollView.showsVerticalScrollIndicator = NO;
    self.scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.scrollView];

    UIView *sv = self.scrollView;
    UIView *prev;

    // ================= 1. INTERCEPTION RULES =================
    UIView *ruleTitle;
    UIView *rulesCard = [self makeCardWithTitle:@"Interception Rules" into:&ruleTitle];

    UILabel *dirLabel = [self rowTitle:@"Capture direction" into:rulesCard above:ruleTitle constant:12];
    self.directionSegment = [self makeSegmentWithItems:@[@"Both", @"Download", @"Upload"]
                                                 parent:rulesCard above:dirLabel constant:8
                                                 action:@selector(directionChanged:)];
    dirLabel.text = @"Capture direction  ·  ↓ Download / ↑ Upload";

    UILabel *protoLabel = [self rowTitle:@"Protocol filter" into:rulesCard above:self.directionSegment constant:16];
    self.protocolSegment = [self makeSegmentWithItems:@[@"TCP + UDP", @"UDP only", @"TCP only"]
                                                parent:rulesCard above:protoLabel constant:8
                                                action:@selector(protocolChanged:)];

    UILabel *modeLabel = [self rowTitle:@"Intercept mode" into:rulesCard above:self.protocolSegment constant:16];
    self.modeSegment = [self makeSegmentWithItems:@[@"Hold", @"Drop", @"Delay", @"Tamper", @"Observe"]
                                            parent:rulesCard above:modeLabel constant:8
                                            action:@selector(modeChanged:)];
    // Five labels no longer fit at equal width: let each segment size itself.
    self.modeSegment.apportionsSegmentWidthsByContent = YES;

    // 4.1.3 — freezing the target is opt-in.  Without pfctl/dnctl and without
    // injection the only way to "hold" traffic is SIGSTOP, which stops the app
    // from rendering at all; the user has to ask for that explicitly.
    self.modeAvailNote = [self rowTitle:@"" into:rulesCard above:self.modeSegment constant:8];
    self.modeAvailNote.font = [AppTheme displayFont:11.5];
    self.modeAvailNote.textColor = [AppTheme colorWarnRed];
    self.modeAvailNote.numberOfLines = 0;
    [NSLayoutConstraint activateConstraints:@[
        [self.modeAvailNote.trailingAnchor constraintEqualToAnchor:rulesCard.trailingAnchor constant:-16],
    ]];

    self.freezeSwitch = [self addSwitchRow:@"Freeze target (SIGSTOP)"
                                    parent:rulesCard above:self.modeAvailNote
                                    action:@selector(freezeToggled:)];

    UILabel *freezeNote = [self rowTitle:@"OFF by default — the app keeps rendering and AetherNet only captures. Turn ON only if you really want to stop the target process."
                                    into:rulesCard above:self.freezeSwitch constant:8];
    freezeNote.font = [AppTheme displayFont:11.5];
    freezeNote.textColor = [AppTheme colorTextSecondary];
    freezeNote.numberOfLines = 0;
    [NSLayoutConstraint activateConstraints:@[
        [freezeNote.trailingAnchor constraintEqualToAnchor:rulesCard.trailingAnchor constant:-16],
    ]];

    self.masterRatioSlider = [self makeSliderRow:@"Master capture ratio"
                                              min:0 max:100 parent:rulesCard
                                            above:freezeNote constant:16
                                            slider:&_masterRatioSlider value:&_masterRatioValue
                                            action:@selector(masterRatioChanged:)];

    self.downloadSlider = [self makeSliderRow:@"Download (RX) hold ratio"
                                           min:0 max:100 parent:rulesCard
                                         above:self.masterRatioSlider constant:10
                                         slider:&_downloadSlider value:&_downloadValue
                                         action:@selector(downloadChanged:)];
    self.downloadSlider.minimumTrackTintColor = [AppTheme colorTCPTeal];

    self.uploadSlider = [self makeSliderRow:@"Upload (TX) hold ratio"
                                         min:0 max:100 parent:rulesCard
                                       above:self.downloadSlider constant:10
                                       slider:&_uploadSlider value:&_uploadValue
                                       action:@selector(uploadChanged:)];
    self.uploadSlider.minimumTrackTintColor = [AppTheme colorUDPBlue];

    [self pinLastControl:self.uploadSlider toCardBottom:rulesCard];

    // ================= 2. NETWORK SIMULATION =================
    UIView *simTitle;
    UIView *simCard = [self makeCardWithTitle:@"Network State Simulation" into:&simTitle];

    UILabel *presetLabel = [self rowTitle:@"Preset" into:simCard above:simTitle constant:12];
    self.presetSegment = [self makeSegmentWithItems:@[@"Normal", @"Ghost", @"Lag", @"3G", @"RST"]
                                              parent:simCard above:presetLabel constant:8
                                              action:@selector(presetChanged:)];

    self.latencySlider = [self makeSliderRow:@"Simulated latency (RTT)"
                                          min:0 max:1500 parent:simCard
                                        above:self.presetSegment constant:16
                                        slider:&_latencySlider value:&_latencyValue
                                        action:@selector(latencyChanged:)];
    self.jitterSlider = [self makeSliderRow:@"Jitter variance"
                                         min:0 max:500 parent:simCard
                                       above:self.latencySlider constant:10
                                       slider:&_jitterSlider value:&_jitterValue
                                       action:@selector(jitterChanged:)];
    self.bandwidthSlider = [self makeSliderRow:@"Bandwidth cap"
                                            min:0 max:100 parent:simCard
                                          above:self.jitterSlider constant:10
                                          slider:&_bandwidthSlider value:&_bandwidthValue
                                          action:@selector(bandwidthChanged:)];
    self.duplicateSlider = [self makeSliderRow:@"Packet duplication (UDP)"
                                            min:0 max:50 parent:simCard
                                          above:self.bandwidthSlider constant:10
                                          slider:&_duplicateSlider value:&_duplicateValue
                                          action:@selector(duplicateChanged:)];

    UILabel *flushLabel = [self rowTitle:@"Safety auto-flush" into:simCard above:self.duplicateSlider constant:16];
    self.autoFlushSegment = [self makeSegmentWithItems:@[@"Off", @"5s", @"12s", @"30s"]
                                                 parent:simCard above:flushLabel constant:8
                                                 action:@selector(autoFlushChanged:)];
    self.lagSpikeSlider = [self makeSliderRow:@"Ping spike (stall the app)"
                                          min:0 max:1000 parent:simCard
                                        above:self.autoFlushSegment constant:16
                                        slider:&_lagSpikeSlider value:&_lagSpikeValue
                                        action:@selector(lagSpikeChanged:)];
    self.lagCycleSlider = [self makeSliderRow:@"Spike every"
                                          min:100 max:2000 parent:simCard
                                        above:self.lagSpikeSlider constant:10
                                        slider:&_lagCycleSlider value:&_lagCycleValue
                                        action:@selector(lagCycleChanged:)];

    UILabel *lagNote = [self rowTitle:@"0 ms = OFF. This is a lag switch: the app is stopped on purpose, so it stutters while a spike is running. Takes effect without restarting interception."
                                 into:simCard above:self.lagCycleSlider constant:8];
    lagNote.font = [AppTheme displayFont:11.5];
    lagNote.textColor = [AppTheme colorTextSecondary];
    lagNote.numberOfLines = 0;
    [NSLayoutConstraint activateConstraints:@[
        [lagNote.trailingAnchor constraintEqualToAnchor:simCard.trailingAnchor constant:-16],
    ]];

    [self pinLastControl:lagNote toCardBottom:simCard];

    // ================= 3. FLOATING BUTTON =================
    UIView *hudTitle;
    UIView *hudCard = [self makeCardWithTitle:@"Floating Button" into:&hudTitle];

    self.sizeSlider = [self makeSliderRow:@"Button diameter"
                                       min:40 max:88 parent:hudCard
                                     above:hudTitle constant:12
                                     slider:&_sizeSlider value:&_sizeValue
                                     action:@selector(sizeChanged:)];
    self.opacitySlider = [self makeSliderRow:@"Opacity"
                                          min:35 max:100 parent:hudCard
                                        above:self.sizeSlider constant:10
                                        slider:&_opacitySlider value:&_opacityValue
                                        action:@selector(opacityChanged:)];

    self.snapSwitch = [self addSwitchRow:@"Snap to screen edge" parent:hudCard above:self.opacitySlider action:@selector(snapToggled:)];
    self.lockSwitch = [self addSwitchRow:@"Lock button position" parent:hudCard above:self.snapSwitch action:@selector(lockToggled:)];
    self.hapticSwitch = [self addSwitchRow:@"Haptic feedback on toggle" parent:hudCard above:self.lockSwitch action:@selector(hapticToggled:)];

    // Manual positioning — works even when the floating button cannot be dragged
    self.xSlider = [self makeSliderRow:@"Floating button — X position"
                                    min:0 max:100 parent:hudCard
                                  above:self.hapticSwitch constant:18
                                  slider:&_xSlider value:&_xValue
                                  action:@selector(xChanged:)];
    self.ySlider = [self makeSliderRow:@"Floating button — Y position"
                                    min:0 max:100 parent:hudCard
                                  above:self.xSlider constant:10
                                  slider:&_ySlider value:&_yValue
                                  action:@selector(yChanged:)];

    [self pinLastControl:self.ySlider toCardBottom:hudCard];

    // ---- Assemble scroll content ----
    [sv addSubview:rulesCard];
    [sv addSubview:simCard];
    [sv addSubview:hudCard];

    rulesCard.translatesAutoresizingMaskIntoConstraints = NO;
    simCard.translatesAutoresizingMaskIntoConstraints = NO;
    hudCard.translatesAutoresizingMaskIntoConstraints = NO;

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [sv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [rulesCard.topAnchor constraintEqualToAnchor:sv.topAnchor constant:16],
        [rulesCard.leadingAnchor constraintEqualToAnchor:sv.leadingAnchor constant:16],
        [rulesCard.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor constant:-16],

        [simCard.topAnchor constraintEqualToAnchor:rulesCard.bottomAnchor constant:14],
        [simCard.leadingAnchor constraintEqualToAnchor:rulesCard.leadingAnchor],
        [simCard.trailingAnchor constraintEqualToAnchor:rulesCard.trailingAnchor],

        [hudCard.topAnchor constraintEqualToAnchor:simCard.bottomAnchor constant:14],
        [hudCard.leadingAnchor constraintEqualToAnchor:rulesCard.leadingAnchor],
        [hudCard.trailingAnchor constraintEqualToAnchor:rulesCard.trailingAnchor],
        [hudCard.bottomAnchor constraintEqualToAnchor:sv.bottomAnchor constant:-30],
    ]];
}

- (void)pinLastControl:(UIView *)control toCardBottom:(UIView *)card {
    [NSLayoutConstraint activateConstraints:@[
        [control.bottomAnchor constraintLessThanOrEqualToAnchor:card.bottomAnchor constant:-16],
        [control.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
    ]];
}

- (UISwitch *)addSwitchRow:(NSString *)title parent:(UIView *)parent above:(UIView *)sibling action:(SEL)action {
    UILabel *label = [AppTheme titleLabelWithText:title];
    label.font = [AppTheme displayFont:13.5];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [parent addSubview:label];

    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.onTintColor = [AppTheme colorGold];
    toggle.translatesAutoresizingMaskIntoConstraints = NO;
    [toggle addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    [parent addSubview:toggle];

    [NSLayoutConstraint activateConstraints:@[
        [label.topAnchor constraintEqualToAnchor:sibling.bottomAnchor constant:18],
        [label.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor constant:16],
        [label.centerYAnchor constraintEqualToAnchor:toggle.centerYAnchor],
        [toggle.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor constant:-16],
    ]];
    return toggle;
}

#pragma mark - Shared State Sync

// Bandwidth slider <-> kbps helpers (logarithmic 64 kbps .. 20000 kbps)
static uint32_t SliderToBandwidth(double sliderValue) {
    if (sliderValue <= 0.5) return 0; // unlimited
    double minBw = 64.0, maxBw = 20000.0;
    double t = (sliderValue - 1.0) / 99.0;
    return (uint32_t)(minBw * pow(maxBw / minBw, t));
}

static int RoundBandwidthToSlider(uint32_t kbps) {
    if (kbps == 0) return 0;               // unlimited — slider position 0
    for (int s = 1; s <= 100; s++) {
        if (SliderToBandwidth((double)s) >= kbps) return s;
    }
    return 100;
}

- (void)notifyConfigChanged {
    notify_post(kAetherNotifyConfigChanged);
    notify_post(kAetherNotifyStateChanged);
}

- (void)loadFromSharedState {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    self.directionSegment.selectedSegmentIndex = aether_atomic_load(&state->direction);
    self.protocolSegment.selectedSegmentIndex = aether_atomic_load(&state->protocolFilter);
    self.modeSegment.selectedSegmentIndex = aether_atomic_load(&state->interceptMode);
    self.freezeSwitch.on = aether_atomic_load(&state->allowFreeze) != 0;

    self.lagSpikeSlider.value = (float)aether_atomic_load(&state->lagSpikeMs);
    self.lagCycleSlider.value = (float)aether_atomic_load(&state->lagCycleMs);
    [self refreshModeAvailability];

    self.masterRatioSlider.value = (float)aether_atomic_load(&state->captureRatioPercent);
    self.downloadSlider.value = (float)aether_atomic_load(&state->downloadHoldPercent);
    self.uploadSlider.value = (float)aether_atomic_load(&state->uploadHoldPercent);

    self.latencySlider.value = (float)aether_atomic_load(&state->simulatedLatencyMs);
    self.jitterSlider.value = (float)aether_atomic_load(&state->simulatedJitterMs);
    self.duplicateSlider.value = (float)aether_atomic_load(&state->duplicatePacketPercent);

    uint32_t kbps = aether_atomic_load(&state->bandwidthLimitKbps);
    // Non-linear mapping: slider 0 = unlimited; 1..100 maps logarithmically 64 kbps .. 20000 kbps
    self.bandwidthSlider.value = (kbps == 0) ? 0.0f : (float)RoundBandwidthToSlider(kbps);

    uint32_t flush = aether_atomic_load(&state->autoFlushSeconds);
    self.autoFlushSegment.selectedSegmentIndex =
        (flush == 0) ? 0 : (flush <= 5) ? 1 : (flush <= 12) ? 2 : 3;

    self.sizeSlider.value = (float)aether_atomic_load(&state->floatingButtonSize);
    self.opacitySlider.value = (float)aether_atomic_load(&state->floatingButtonOpacity) * 100.0f;
    self.snapSwitch.on = aether_atomic_load(&state->floatingEdgeSnap);
    self.lockSwitch.on = aether_atomic_load(&state->floatingLockPosition);
    self.hapticSwitch.on = aether_atomic_load(&state->floatingHapticEnabled);

    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;
    self.xSlider.value = (float)MAX(0, MIN(100, ((CGFloat)aether_atomic_load(&state->floatingPosX) - 20.0) / (sw - 40.0) * 100.0));
    self.ySlider.value = (float)MAX(0, MIN(100, ((CGFloat)aether_atomic_load(&state->floatingPosY) - 80.0) / (sh - 120.0) * 100.0));

    self.presetSegment.selectedSegmentIndex =
        MAX(0, (int)aether_atomic_load(&state->activePreset) - 1);

    [self refreshAllValueLabels];
}

- (void)refreshAllValueLabels {
    uint32_t bw = SliderToBandwidth(self.bandwidthSlider.value);
    self.bandwidthValue.text = (bw == 0) ? @"Unlimited" :
        (bw >= 1024 ? [NSString stringWithFormat:@"%.1f Mbps", bw / 1024.0]
                    : [NSString stringWithFormat:@"%u kbps", bw]);

    self.masterRatioValue.text = [NSString stringWithFormat:@"%d %%", (int)self.masterRatioSlider.value];
    self.downloadValue.text = [NSString stringWithFormat:@"%d %%", (int)self.downloadSlider.value];
    self.uploadValue.text = [NSString stringWithFormat:@"%d %%", (int)self.uploadSlider.value];
    self.latencyValue.text = [NSString stringWithFormat:@"%d ms", (int)self.latencySlider.value];
    self.jitterValue.text = [NSString stringWithFormat:@"%d ms", (int)self.jitterSlider.value];
    self.duplicateValue.text = [NSString stringWithFormat:@"%d %%", (int)self.duplicateSlider.value];
    int spike = ((int)self.lagSpikeSlider.value / 10) * 10;
    int cycle = ((int)self.lagCycleSlider.value / 100) * 100;
    self.lagSpikeValue.text = (spike < 10) ? @"off" : [NSString stringWithFormat:@"%d ms", spike];
    self.lagCycleValue.text = [NSString stringWithFormat:@"%d ms", cycle];
    self.sizeValue.text = [NSString stringWithFormat:@"%d pt", (int)self.sizeSlider.value];
    self.opacityValue.text = [NSString stringWithFormat:@"%d %%", (int)self.opacitySlider.value];
    self.xValue.text = [NSString stringWithFormat:@"%d %%", (int)self.xSlider.value];
    self.yValue.text = [NSString stringWithFormat:@"%d %%", (int)self.ySlider.value];
}

#pragma mark - Capture Rule Handlers

- (void)directionChanged:(UISegmentedControl *)seg {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->direction, (uint8_t)seg.selectedSegmentIndex);
    [self notifyConfigChanged];
}

- (void)protocolChanged:(UISegmentedControl *)seg {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->protocolFilter, (uint8_t)seg.selectedSegmentIndex);
    [self notifyConfigChanged];
}

- (void)modeChanged:(UISegmentedControl *)seg {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->interceptMode, (uint8_t)seg.selectedSegmentIndex);
    [self notifyConfigChanged];
}

- (void)freezeToggled:(UISwitch *)toggle {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->allowFreeze, (uint8_t)(toggle.on ? 1 : 0));
    [self refreshModeAvailability];
    [self notifyConfigChanged];
}

- (void)lagSpikeChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    uint32_t v = (((uint32_t)slider.value) / 10u) * 10u;
    if (v < 10u) v = 0u;
    if (state) aether_atomic_store(&state->lagSpikeMs, v);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)lagCycleChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    uint32_t v = (((uint32_t)slider.value) / 100u) * 100u;
    if (v < 100u) v = 100u;
    if (state) aether_atomic_store(&state->lagCycleMs, v);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

// Grey out every mode this device cannot enforce instead of letting the user
// pick something that will silently do nothing.
- (void)refreshModeAvailability {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    uint32_t caps = AetherShaperCapabilities();
    BOOL injected = aether_atomic_load(&state->isInjected) != 0;
    BOOL canQueue = injected ||
                    (caps & (AETHER_SHAPER_CAP_PFCTL | AETHER_SHAPER_CAP_DUMMYNET)) != 0;
    BOOL canHoldOrDrop = canQueue ||
                    (aether_atomic_load(&state->allowFreeze) &&
                     (caps & AETHER_SHAPER_CAP_FREEZE));

    [self.modeSegment setEnabled:canHoldOrDrop forSegmentAtIndex:0];   // Hold
    [self.modeSegment setEnabled:canHoldOrDrop forSegmentAtIndex:1];   // Drop
    [self.modeSegment setEnabled:canQueue      forSegmentAtIndex:2];   // Delay
    [self.modeSegment setEnabled:canQueue      forSegmentAtIndex:3];   // Tamper
    [self.modeSegment setEnabled:YES           forSegmentAtIndex:4];   // Observe

    uint8_t mode = aether_atomic_load(&state->interceptMode);
    BOOL currentOK = (mode == AetherModeObserve) ? YES
                   : ((mode == AetherModeHoldQueue || mode == AetherModeDropPacket)
                        ? canHoldOrDrop : canQueue);
    if (!currentOK) {
        aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeObserve);
        self.modeSegment.selectedSegmentIndex = AetherModeObserve;
    }

    if (canQueue) {
        self.modeAvailNote.text = @"";
    } else if (canHoldOrDrop) {
        self.modeAvailNote.text = @"Delay / Tamper: unavailable - this device has no pfctl/dnctl and the in-process hook could not be loaded.";
    } else {
        self.modeAvailNote.text = @"Only Observe can run here (no pfctl, no dnctl, injection unavailable). Hold / Drop need 'Freeze target' below.";
    }
}

- (void)masterRatioChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->captureRatioPercent, (uint32_t)slider.value);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)downloadChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->downloadHoldPercent, (uint32_t)slider.value);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)uploadChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->uploadHoldPercent, (uint32_t)slider.value);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

#pragma mark - Simulation Handlers

- (void)applyPreset:(AetherNetworkPreset)preset {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    switch (preset) {
        case AetherPresetNormal:
            aether_atomic_store(&state->simulatedLatencyMs, 30);
            aether_atomic_store(&state->simulatedJitterMs, 5);
            aether_atomic_store(&state->bandwidthLimitKbps, 0);
            aether_atomic_store(&state->captureRatioPercent, 0);
            aether_atomic_store(&state->downloadHoldPercent, 0);
            aether_atomic_store(&state->uploadHoldPercent, 0);
            aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeDelayJitter);
            break;

        case AetherPresetGhostFreeze:
            aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeHoldQueue);
            aether_atomic_store(&state->captureRatioPercent, 98);
            aether_atomic_store(&state->downloadHoldPercent, 95);
            aether_atomic_store(&state->uploadHoldPercent, 98);
            aether_atomic_store(&state->protocolFilter, (uint8_t)AetherProtoUDPOnly);
            aether_atomic_store(&state->simulatedLatencyMs, 0);
            aether_atomic_store(&state->simulatedJitterMs, 0);
            aether_atomic_store(&state->bandwidthLimitKbps, 0);
            break;

        case AetherPresetLagSpike:
            aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeDelayJitter);
            aether_atomic_store(&state->simulatedLatencyMs, 450);
            aether_atomic_store(&state->simulatedJitterMs, 120);
            aether_atomic_store(&state->captureRatioPercent, 25);
            aether_atomic_store(&state->protocolFilter, (uint8_t)AetherProtoUDPOnly);
            aether_atomic_store(&state->bandwidthLimitKbps, 0);
            break;

        case AetherPresetDegraded3G:
            aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeDelayJitter);
            aether_atomic_store(&state->simulatedLatencyMs, 280);
            aether_atomic_store(&state->simulatedJitterMs, 60);
            aether_atomic_store(&state->bandwidthLimitKbps, 128);
            aether_atomic_store(&state->captureRatioPercent, 15);
            aether_atomic_store(&state->protocolFilter, (uint8_t)AetherProtoTCPAndUDP);
            break;

        case AetherPresetTCPReset:
            aether_atomic_store(&state->interceptMode, (uint8_t)AetherModeDropPacket);
            aether_atomic_store(&state->captureRatioPercent, 60);
            aether_atomic_store(&state->protocolFilter, (uint8_t)AetherProtoTCPOnly);
            aether_atomic_store(&state->simulatedLatencyMs, 200);
            aether_atomic_store(&state->simulatedJitterMs, 80);
            aether_atomic_store(&state->bandwidthLimitKbps, 256);
            break;

        default:
            break;
    }

    aether_atomic_store(&state->activePreset, (uint8_t)preset);
    [self loadFromSharedState];
    [self notifyConfigChanged];
}

- (void)presetChanged:(UISegmentedControl *)seg {
    [self applyPreset:(AetherNetworkPreset)(seg.selectedSegmentIndex + 1)];
}

- (void)latencyChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        aether_atomic_store(&state->simulatedLatencyMs, (uint32_t)slider.value);
        aether_atomic_store(&state->activePreset, (uint8_t)AetherPresetCustom);
    }
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)jitterChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        aether_atomic_store(&state->simulatedJitterMs, (uint32_t)slider.value);
        aether_atomic_store(&state->activePreset, (uint8_t)AetherPresetCustom);
    }
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)bandwidthChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        aether_atomic_store(&state->bandwidthLimitKbps, SliderToBandwidth(slider.value));
        aether_atomic_store(&state->activePreset, (uint8_t)AetherPresetCustom);
    }
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)duplicateChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->duplicatePacketPercent, (uint32_t)slider.value);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)autoFlushChanged:(UISegmentedControl *)seg {
    AetherSharedState *state = AetherGetSharedState();
    uint32_t seconds = 0;
    switch (seg.selectedSegmentIndex) {
        case 1: seconds = 5; break;
        case 2: seconds = 12; break;
        case 3: seconds = 30; break;
        default: seconds = 0; break;
    }
    if (state) aether_atomic_store(&state->autoFlushSeconds, seconds);
    [self notifyConfigChanged];
}

#pragma mark - Floating Button Handlers

- (void)sizeChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->floatingButtonSize, (float)slider.value);
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)opacityChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->floatingButtonOpacity, (float)(slider.value / 100.0));
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)snapToggled:(UISwitch *)toggle {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->floatingEdgeSnap, toggle.on);
    [self notifyConfigChanged];
}

- (void)lockToggled:(UISwitch *)toggle {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->floatingLockPosition, toggle.on);
    [self notifyConfigChanged];
}

- (void)hapticToggled:(UISwitch *)toggle {
    AetherSharedState *state = AetherGetSharedState();
    if (state) aether_atomic_store(&state->floatingHapticEnabled, toggle.on);
    [self notifyConfigChanged];
}

- (void)xChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        CGFloat w = [UIScreen mainScreen].bounds.size.width;
        aether_atomic_store(&state->floatingPosX, (float)(slider.value / 100.0 * (w - 40.0) + 20.0));
    }
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

- (void)yChanged:(UISlider *)slider {
    AetherSharedState *state = AetherGetSharedState();
    if (state) {
        CGFloat h = [UIScreen mainScreen].bounds.size.height;
        aether_atomic_store(&state->floatingPosY, (float)(slider.value / 100.0 * (h - 120.0) + 80.0));
    }
    [self refreshAllValueLabels];
    [self notifyConfigChanged];
}

@end
