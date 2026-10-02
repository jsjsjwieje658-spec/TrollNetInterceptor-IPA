//
//  HomeViewController.mm
//  AetherNet — Tab 1: Home
//
//  Layout:
//   1. Brand header (AetherNet crest + status pill)
//   2. TARGET PROCESS card:
//        - Large rectangle box (tap to open PID picker sheet)
//        - Selected process metadata (icon / name / PID / bundle / injection state)
//   3. NETWORK STATUS card:
//        - TCP lane & UDP lane with live socket counts, RX/TX rates and packets
//        - Held / dropped packets counters
//   4. GLOBAL FLOATING HUD card:
//        - Mini preview of the circular button (logo ring + ▶/⏸)
//        - "Create Floating Button" primary action
//

#import "HomeViewController.h"
#import "AppTheme.h"
#import "AetherGoldButton.h"
#import "../Core/AetherLog.h"
#import "../Core/ProcessManager.h"
#import "../headers/AetherNetShared.h"
#import "../headers/PrivateSystemSPI.h"
#include <notify.h>

#pragma mark - Process Picker (Rectangle Box Tap Target)

@interface ProcessPickerViewController : UIViewController <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@property (nonatomic, copy) void (^onProcessSelected)(AetherProcessInfo *);
@end

@implementation ProcessPickerViewController {
    UISearchBar *_searchBar;
    UITableView *_table;
    NSArray<AetherProcessInfo *> *_allProcesses;
    NSArray<AetherProcessInfo *> *_visibleProcesses;
    UISegmentedControl *_scopeSegment;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [AppTheme colorObsidian];

    UILabel *title = [AppTheme titleLabelWithText:@"Select Target Process"];
    UILabel *subtitle = [AppTheme valueLabelWithText:@"Choose a running PID to inject & monitor L4 traffic" mono:NO];

    _scopeSegment = [[UISegmentedControl alloc] initWithItems:@[@"User Apps", @"All Processes"]];
    _scopeSegment.selectedSegmentIndex = 0;
    [_scopeSegment addTarget:self action:@selector(scopeChanged) forControlEvents:UIControlEventValueChanged];
    [AppTheme styleSegmentedControl:_scopeSegment];

    _searchBar = [[UISearchBar alloc] init];
    _searchBar.delegate = self;
    _searchBar.placeholder = @"Search name, PID or bundle id…";
    _searchBar.barStyle = UIBarStyleBlack;
    _searchBar.searchBarStyle = UISearchBarStyleMinimal;
    _searchBar.tintColor = [AppTheme colorGold];

    _table = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _table.dataSource = self;
    _table.delegate = self;
    _table.backgroundColor = [UIColor clearColor];
    _table.separatorStyle = UITableViewCellSeparatorStyleNone;
    _table.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [_table registerClass:[UITableViewCell class] forCellReuseIdentifier:@"proc"];

    [self.view addSubview:title];
    [self.view addSubview:subtitle];
    [self.view addSubview:_scopeSegment];
    [self.view addSubview:_searchBar];
    [self.view addSubview:_table];

    title.translatesAutoresizingMaskIntoConstraints = NO;
    subtitle.translatesAutoresizingMaskIntoConstraints = NO;
    _scopeSegment.translatesAutoresizingMaskIntoConstraints = NO;
    _searchBar.translatesAutoresizingMaskIntoConstraints = NO;
    _table.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:18],
        [title.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:20],
        [subtitle.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4],
        [subtitle.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [_scopeSegment.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:14],
        [_scopeSegment.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [_scopeSegment.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-20],
        [_scopeSegment.heightAnchor constraintEqualToConstant:34],
        [_searchBar.topAnchor constraintEqualToAnchor:_scopeSegment.bottomAnchor constant:10],
        [_searchBar.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [_searchBar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [_table.topAnchor constraintEqualToAnchor:_searchBar.bottomAnchor constant:4],
        [_table.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_table.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_table.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];

    UIBarButtonItem *close = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemStop
                                                                           target:self action:@selector(dismissTapped)];
    close.tintColor = [AppTheme colorGoldMuted];
    self.navigationItem.rightBarButtonItem = close;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadData];
}

- (void)reloadData {
    _allProcesses = [[AetherProcessManager sharedManager]
        enumerateRunningProcessesWithFilter:nil
                               onlyUserApps:(_scopeSegment.selectedSegmentIndex == 0)];
    _visibleProcesses = _allProcesses;
    [_table reloadData];
}

- (void)scopeChanged {
    [self reloadData];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    if (searchText.length == 0) {
        _visibleProcesses = _allProcesses;
    } else {
        NSString *q = [searchText lowercaseString];
        NSMutableArray *filtered = [NSMutableArray array];
        for (AetherProcessInfo *info in _allProcesses) {
            if ([info.displayName.lowercaseString containsString:q] ||
                [info.bundleIdentifier.lowercaseString containsString:q] ||
                [[NSString stringWithFormat:@"%d", info.pid] containsString:q]) {
                [filtered addObject:info];
            }
        }
        _visibleProcesses = filtered;
    }
    [_table reloadData];
}

- (void)dismissTapped {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return _visibleProcesses.count;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 72.0;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"proc" forIndexPath:indexPath];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.backgroundColor = [UIColor clearColor];

    AetherProcessInfo *info = _visibleProcesses[indexPath.row];
    CGFloat size = 48.0;

    UIView *iconHost = [cell viewWithTag:101];
    UILabel *name = [cell viewWithTag:102];
    UILabel *detail = [cell viewWithTag:103];
    UILabel *socketBadge = [cell viewWithTag:104];
    UIView *card = [cell viewWithTag:105];

    if (!card) {
        card = [AppTheme cardContainerView];
        card.tag = 105;
        [cell.contentView addSubview:card];

        iconHost = [[UIView alloc] init];
        iconHost.tag = 101;
        iconHost.layer.cornerRadius = 11.0;
        iconHost.clipsToBounds = YES;
        iconHost.backgroundColor = [AppTheme colorObsidian];
        [card addSubview:iconHost];

        name = [AppTheme titleLabelWithText:@""];
        name.font = [AppTheme displayFont:14.5];
        name.tag = 102;
        [card addSubview:name];

        detail = [AppTheme valueLabelWithText:@"" mono:YES];
        detail.tag = 103;
        [card addSubview:detail];

        socketBadge = [AppTheme valueLabelWithText:@"" mono:YES];
        socketBadge.tag = 104;
        socketBadge.font = [AppTheme monoFont:11.0];
        socketBadge.textAlignment = NSTextAlignmentRight;
        [card addSubview:socketBadge];

        card.translatesAutoresizingMaskIntoConstraints = NO;
        iconHost.translatesAutoresizingMaskIntoConstraints = NO;
        name.translatesAutoresizingMaskIntoConstraints = NO;
        detail.translatesAutoresizingMaskIntoConstraints = NO;
        socketBadge.translatesAutoresizingMaskIntoConstraints = NO;

        [NSLayoutConstraint activateConstraints:@[
            [card.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:5],
            [card.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:14],
            [card.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-14],
            [card.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-5],
            [iconHost.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
            [iconHost.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
            [iconHost.widthAnchor constraintEqualToConstant:size],
            [iconHost.heightAnchor constraintEqualToConstant:size],
            [name.topAnchor constraintEqualToAnchor:card.topAnchor constant:12],
            [name.leadingAnchor constraintEqualToAnchor:iconHost.trailingAnchor constant:12],
            [name.trailingAnchor constraintLessThanOrEqualToAnchor:socketBadge.leadingAnchor constant:-8],
            [detail.topAnchor constraintEqualToAnchor:name.bottomAnchor constant:3],
            [detail.leadingAnchor constraintEqualToAnchor:name.leadingAnchor],
            [detail.trailingAnchor constraintLessThanOrEqualToAnchor:card.trailingAnchor constant:-12],
            [socketBadge.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-12],
            [socketBadge.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        ]];
    }

    // Clear previous icon subviews and refresh
    for (UIView *sub in iconHost.subviews) [sub removeFromSuperview];
    if (info.appIcon) {
        UIImageView *iv = [[UIImageView alloc] initWithImage:info.appIcon];
        iv.frame = iconHost.bounds;
        iv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [iconHost addSubview:iv];
    } else {
        UILabel *ph = [[UILabel alloc] init];
        ph.frame = iconHost.bounds;
        ph.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        ph.text = (info.displayName.length > 0)
            ? [[info.displayName substringToIndex:1] uppercaseString]
            : @"?";
        ph.font = [AppTheme displayFont:20.0];
        ph.textColor = [AppTheme colorGoldMuted];
        ph.textAlignment = NSTextAlignmentCenter;
        [iconHost addSubview:ph];
    }

    name.text = info.displayName;
    detail.text = [NSString stringWithFormat:@"PID %d · %@", info.pid, info.bundleIdentifier];
    if (info.isUserApp) {
        name.textColor = [AppTheme colorTextPrimary];
    } else {
        name.textColor = [AppTheme colorTextSecondary];
    }

    if (info.tcpSocketCount + info.udpSocketCount > 0) {
        socketBadge.textColor = [AppTheme colorTCPTeal];
        socketBadge.text = [NSString stringWithFormat:@"TCP %u · UDP %u", info.tcpSocketCount, info.udpSocketCount];
    } else {
        socketBadge.textColor = [AppTheme colorTextSecondary];
        socketBadge.text = @"no sockets";
    }

    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    AetherProcessInfo *info = _visibleProcesses[indexPath.row];
    if (self.onProcessSelected) self.onProcessSelected(info);
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end

#pragma mark - Home Tab

@interface HomeViewController ()
@property (nonatomic, strong) UIScrollView *scrollView;
@property (nonatomic, strong) UIView *targetBox;
@property (nonatomic, strong) UILabel *boxTitle;
@property (nonatomic, strong) UILabel *boxSubtitle;
@property (nonatomic, strong) UIImageView *boxIcon;
@property (nonatomic, strong) UILabel *injectPill;
@property (nonatomic, strong) UILabel *tcpStatLabel;
@property (nonatomic, strong) UILabel *udpStatLabel;
@property (nonatomic, strong) UILabel *tcpRateLabel;
@property (nonatomic, strong) UILabel *udpRateLabel;
@property (nonatomic, strong) UIView *tcpBar;
@property (nonatomic, strong) UIView *udpBar;
@property (nonatomic, strong) UILabel *heldLabel;
@property (nonatomic, strong) UILabel *droppedLabel;
@property (nonatomic, strong) UILabel *modeLabel;
@property (nonatomic, strong) AetherGoldButton *spawnHUDButton;
@property (nonatomic, strong) UILabel *hudStatus;
@property (nonatomic, strong) AetherGoldButton *toggleButton;
@property (nonatomic, strong) AetherGoldButton *viewLogButton;
@property (nonatomic, strong) UILabel *debugLabel;
@property (nonatomic, strong) NSTimer *ticker;
@property (nonatomic, assign) BOOL lastHUDRunningState;
@end


// Fix "blank Home tab": mọi view con buộc tham gia Auto Layout thuần.
// Bất kỳ view nào còn giữ autoresizing mask (translates = YES) sẽ sinh
// constraint xung đột → UIKit phá 1 constraint → phần tử về frame 0x0
// → tab trông như trắng trơn và nút bấm không thể chạm.
static void AetherDisableAutoresizingTranslates(UIView *view)
{
    view.translatesAutoresizingMaskIntoConstraints = NO;
    for (UIView *sub in view.subviews) {
        AetherDisableAutoresizingTranslates(sub);
    }
}

@implementation HomeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [AppTheme colorObsidian];
    self.title = @"Home";
    [self buildUI];
    [self startTicker];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    for (CALayer *sub in self.view.layer.sublayers) {
        if ([sub isKindOfClass:[CAGradientLayer class]]) {
            sub.frame = self.view.bounds;
        }
    }
    [self syncSpawnButtonLayout];
}

- (void)buildUI {
    CAGradientLayer *bg = [AppTheme brandGradientLayer];
    bg.frame = self.view.bounds;
    [self.view.layer insertSublayer:bg atIndex:0];

    self.scrollView = [[UIScrollView alloc] init];
    self.scrollView.alwaysBounceVertical = YES;
    self.scrollView.showsVerticalScrollIndicator = NO;
    [self.view addSubview:self.scrollView];

    // ---- Brand header -------------------------------------------------
    UILabel *brand = [AppTheme titleLabelWithText:@"AetherNet"];
    brand.font = [AppTheme displayFont:22.0];

    UILabel *brandSub = [AppTheme valueLabelWithText:@"Low-level TCP / UDP packet interceptor" mono:NO];

    // ---- Card 1: Target Process ---------------------------------------
    UIView *targetCard = [AppTheme cardContainerView];
    UILabel *targetHeader = [AppTheme sectionHeaderWithText:@"Target Process"];

    self.targetBox = [[UIView alloc] init];
    self.targetBox.backgroundColor = [AppTheme colorObsidian];
    self.targetBox.layer.cornerRadius = 14.0;
    self.targetBox.layer.borderWidth = 1.5;
    self.targetBox.layer.borderColor = [[AppTheme colorGoldMuted] colorWithAlphaComponent:0.35].CGColor;
    UITapGestureRecognizer *boxTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(openProcessPicker)];
    [self.targetBox addGestureRecognizer:boxTap];

    self.boxIcon = [[UIImageView alloc] init];
    self.boxIcon.contentMode = UIViewContentModeScaleAspectFit;
    self.boxIcon.layer.cornerRadius = 12.0;
    self.boxIcon.clipsToBounds = YES;
    self.boxIcon.hidden = YES;

    self.boxTitle = [AppTheme titleLabelWithText:@"Tap to select process"];
    self.boxTitle.font = [AppTheme displayFont:17.0];

    self.boxSubtitle = [AppTheme valueLabelWithText:@"Choose the PID to inject libNetHookPayload.dylib" mono:NO];
    self.boxSubtitle.numberOfLines = 2;

    self.injectPill = [[UILabel alloc] init];
    self.injectPill.font = [AppTheme displayFont:10.5];
    self.injectPill.textAlignment = NSTextAlignmentCenter;
    self.injectPill.layer.cornerRadius = 9.0;
    self.injectPill.clipsToBounds = YES;
    self.injectPill.text = @"  NOT INJECTED  ";

    [targetCard addSubview:targetHeader];
    [targetCard addSubview:self.targetBox];
    [self.targetBox addSubview:self.boxIcon];
    [self.targetBox addSubview:self.boxTitle];
    [self.targetBox addSubview:self.boxSubtitle];
    [self.targetBox addSubview:self.injectPill];

    // ---- Card 2: Network Status ---------------------------------------
    UIView *netCard = [AppTheme cardContainerView];
    UILabel *netHeader = [AppTheme sectionHeaderWithText:@"L4 Network Status"];

    UILabel *tcpLaneTitle = [AppTheme titleLabelWithText:@"TCP"];
    tcpLaneTitle.font = [AppTheme displayFont:14.0];
    tcpLaneTitle.textColor = [AppTheme colorTCPTeal];
    self.tcpStatLabel = [AppTheme valueLabelWithText:@"0 sockets · 0 pkts" mono:YES];
    self.tcpRateLabel = [AppTheme valueLabelWithText:@"↓ 0 B/s · ↑ 0 B/s" mono:YES];

    UILabel *udpLaneTitle = [AppTheme titleLabelWithText:@"UDP"];
    udpLaneTitle.font = [AppTheme displayFont:14.0];
    udpLaneTitle.textColor = [AppTheme colorUDPBlue];
    self.udpStatLabel = [AppTheme valueLabelWithText:@"0 sockets · 0 pkts" mono:YES];
    self.udpRateLabel = [AppTheme valueLabelWithText:@"↓ 0 B/s · ↑ 0 B/s" mono:YES];

    self.tcpBar = [[UIView alloc] init];
    self.tcpBar.backgroundColor = [AppTheme colorTCPTeal];
    self.tcpBar.layer.cornerRadius = 2.0;

    self.udpBar = [[UIView alloc] init];
    self.udpBar.backgroundColor = [AppTheme colorUDPBlue];
    self.udpBar.layer.cornerRadius = 2.0;

    self.modeLabel = [AppTheme valueLabelWithText:@"Mode: Hold Queue · Both directions" mono:NO];

    self.heldLabel = [AppTheme valueLabelWithText:@"Held: 0 pkts" mono:YES];
    self.droppedLabel = [AppTheme valueLabelWithText:@"Dropped: 0 pkts" mono:YES];
    self.droppedLabel.textColor = [AppTheme colorWarnRed];

    [netCard addSubview:netHeader];
    [netCard addSubview:tcpLaneTitle];
    [netCard addSubview:self.tcpStatLabel];
    [netCard addSubview:self.tcpRateLabel];
    [netCard addSubview:self.tcpBar];
    [netCard addSubview:udpLaneTitle];
    [netCard addSubview:self.udpStatLabel];
    [netCard addSubview:self.udpRateLabel];
    [netCard addSubview:self.udpBar];
    [netCard addSubview:self.modeLabel];
    [netCard addSubview:self.heldLabel];
    [netCard addSubview:self.droppedLabel];

    // ---- Card 3: Global Floating HUD ----------------------------------
    UIView *hudCard = [AppTheme cardContainerView];
    UILabel *hudHeader = [AppTheme sectionHeaderWithText:@"Global Floating Button"];

    self.toggleButton = [[AetherGoldButton alloc] initWithTitle:@"▶ Start intercepting"];
    [self.toggleButton applySecondaryStyle];

    // Custom UIControl — immune to the UIButtonLegacyVisualProvider KVO crash
    self.spawnHUDButton = [[AetherGoldButton alloc] initWithTitle:@"Create Floating Button"];

    self.hudStatus = [AppTheme valueLabelWithText:@"HUD daemon: offline" mono:YES];
    self.debugLabel = [AppTheme valueLabelWithText:@"touch debug — waiting for HUD…" mono:YES];
    self.debugLabel.font = [AppTheme monoFont:9.5];
    self.debugLabel.textAlignment = NSTextAlignmentCenter;

    self.viewLogButton = [[AetherGoldButton alloc] initWithTitle:@"📄 View / Share log"];
    [self.viewLogButton applySecondaryStyle];
    [hudCard addSubview:hudHeader];
    [hudCard addSubview:self.toggleButton];
    [hudCard addSubview:self.spawnHUDButton];
    [hudCard addSubview:self.hudStatus];
    [hudCard addSubview:self.debugLabel];
    [hudCard addSubview:self.viewLogButton];

    [self.spawnHUDButton addTarget:self action:@selector(spawnHUDTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.toggleButton addTarget:self action:@selector(toggleInterceptionTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.viewLogButton addTarget:self action:@selector(viewLogTapped) forControlEvents:UIControlEventTouchUpInside];

    // ---- Autolayout ----------------------------------------------------
    UIView *sv = self.scrollView;
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    brand.translatesAutoresizingMaskIntoConstraints = NO;
    brandSub.translatesAutoresizingMaskIntoConstraints = NO;
    targetCard.translatesAutoresizingMaskIntoConstraints = NO;
    netCard.translatesAutoresizingMaskIntoConstraints = NO;
    hudCard.translatesAutoresizingMaskIntoConstraints = NO;

    [self.view addSubview:sv];
    [sv addSubview:brand];
    [sv addSubview:brandSub];
    [sv addSubview:targetCard];
    [sv addSubview:netCard];
    [sv addSubview:hudCard];

    for (UIView *v in @[targetHeader, targetCard, netCard, hudCard, hudHeader, netHeader]) {
        v.translatesAutoresizingMaskIntoConstraints = NO;
    }

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;

    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [sv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [brand.topAnchor constraintEqualToAnchor:sv.topAnchor constant:18],
        [brand.leadingAnchor constraintEqualToAnchor:sv.leadingAnchor constant:20],
        [brandSub.topAnchor constraintEqualToAnchor:brand.bottomAnchor constant:4],
        [brandSub.leadingAnchor constraintEqualToAnchor:brand.leadingAnchor],

        [targetCard.topAnchor constraintEqualToAnchor:brandSub.bottomAnchor constant:10],
        [targetCard.leadingAnchor constraintEqualToAnchor:sv.leadingAnchor constant:16],
        [targetCard.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor constant:-16],

        [netCard.topAnchor constraintEqualToAnchor:targetCard.bottomAnchor constant:10],
        [netCard.leadingAnchor constraintEqualToAnchor:targetCard.leadingAnchor],
        [netCard.trailingAnchor constraintEqualToAnchor:targetCard.trailingAnchor],

        [hudCard.topAnchor constraintEqualToAnchor:netCard.bottomAnchor constant:10],
        [hudCard.leadingAnchor constraintEqualToAnchor:targetCard.leadingAnchor],
        [hudCard.trailingAnchor constraintEqualToAnchor:targetCard.trailingAnchor],
        [hudCard.bottomAnchor constraintEqualToAnchor:sv.bottomAnchor constant:-30],

        [targetHeader.topAnchor constraintEqualToAnchor:targetCard.topAnchor constant:14],
        [targetHeader.leadingAnchor constraintEqualToAnchor:targetCard.leadingAnchor constant:16],

        [self.targetBox.topAnchor constraintEqualToAnchor:targetHeader.bottomAnchor constant:10],
        [self.targetBox.leadingAnchor constraintEqualToAnchor:targetCard.leadingAnchor constant:14],
        [self.targetBox.trailingAnchor constraintEqualToAnchor:targetCard.trailingAnchor constant:-14],
        [self.targetBox.heightAnchor constraintEqualToConstant:92],

        [self.boxIcon.leadingAnchor constraintEqualToAnchor:self.targetBox.leadingAnchor constant:16],
        [self.boxIcon.centerYAnchor constraintEqualToAnchor:self.targetBox.centerYAnchor],
        [self.boxIcon.widthAnchor constraintEqualToConstant:48],
        [self.boxIcon.heightAnchor constraintEqualToConstant:48],

        [self.boxTitle.topAnchor constraintEqualToAnchor:self.targetBox.topAnchor constant:14],
        [self.boxTitle.leadingAnchor constraintEqualToAnchor:self.boxIcon.trailingAnchor constant:14],
        [self.boxTitle.trailingAnchor constraintLessThanOrEqualToAnchor:self.targetBox.trailingAnchor constant:-14],

        [self.boxSubtitle.topAnchor constraintEqualToAnchor:self.boxTitle.bottomAnchor constant:4],
        [self.boxSubtitle.leadingAnchor constraintEqualToAnchor:self.boxTitle.leadingAnchor],
        [self.boxSubtitle.trailingAnchor constraintEqualToAnchor:self.targetBox.trailingAnchor constant:-14],

        [self.injectPill.topAnchor constraintEqualToAnchor:self.boxSubtitle.bottomAnchor constant:8],
        [self.injectPill.leadingAnchor constraintEqualToAnchor:self.boxTitle.leadingAnchor],
        [self.injectPill.heightAnchor constraintEqualToConstant:18],
        [self.injectPill.bottomAnchor constraintEqualToAnchor:targetCard.bottomAnchor constant:-14],

        [netHeader.topAnchor constraintEqualToAnchor:netCard.topAnchor constant:14],
        [netHeader.leadingAnchor constraintEqualToAnchor:netCard.leadingAnchor constant:16],

        [tcpLaneTitle.topAnchor constraintEqualToAnchor:netHeader.bottomAnchor constant:10],
        [tcpLaneTitle.leadingAnchor constraintEqualToAnchor:netCard.leadingAnchor constant:16],
        [self.tcpStatLabel.centerYAnchor constraintEqualToAnchor:tcpLaneTitle.centerYAnchor],
        [self.tcpStatLabel.trailingAnchor constraintEqualToAnchor:netCard.trailingAnchor constant:-16],
        [self.tcpStatLabel.leadingAnchor constraintGreaterThanOrEqualToAnchor:tcpLaneTitle.trailingAnchor constant:8],
        [self.tcpRateLabel.topAnchor constraintEqualToAnchor:tcpLaneTitle.bottomAnchor constant:2],
        [self.tcpRateLabel.leadingAnchor constraintEqualToAnchor:tcpLaneTitle.leadingAnchor],
        [self.tcpBar.topAnchor constraintEqualToAnchor:self.tcpRateLabel.bottomAnchor constant:6],
        [self.tcpBar.leadingAnchor constraintEqualToAnchor:netCard.leadingAnchor constant:16],
        [self.tcpBar.heightAnchor constraintEqualToConstant:3],
        [self.tcpBar.widthAnchor constraintEqualToConstant:96],

        [udpLaneTitle.topAnchor constraintEqualToAnchor:self.tcpBar.bottomAnchor constant:10],
        [udpLaneTitle.leadingAnchor constraintEqualToAnchor:tcpLaneTitle.leadingAnchor],
        [self.udpStatLabel.centerYAnchor constraintEqualToAnchor:udpLaneTitle.centerYAnchor],
        [self.udpStatLabel.trailingAnchor constraintEqualToAnchor:netCard.trailingAnchor constant:-16],
        [self.udpStatLabel.leadingAnchor constraintGreaterThanOrEqualToAnchor:udpLaneTitle.trailingAnchor constant:8],
        [self.udpRateLabel.topAnchor constraintEqualToAnchor:udpLaneTitle.bottomAnchor constant:2],
        [self.udpRateLabel.leadingAnchor constraintEqualToAnchor:udpLaneTitle.leadingAnchor],
        [self.udpBar.topAnchor constraintEqualToAnchor:self.udpRateLabel.bottomAnchor constant:6],
        [self.udpBar.leadingAnchor constraintEqualToAnchor:self.tcpBar.leadingAnchor],
        [self.udpBar.heightAnchor constraintEqualToConstant:3],
        [self.udpBar.widthAnchor constraintEqualToConstant:96],

        [self.modeLabel.topAnchor constraintEqualToAnchor:self.udpBar.bottomAnchor constant:10],
        [self.modeLabel.leadingAnchor constraintEqualToAnchor:tcpLaneTitle.leadingAnchor],
        [self.heldLabel.topAnchor constraintEqualToAnchor:self.modeLabel.bottomAnchor constant:4],
        [self.heldLabel.leadingAnchor constraintEqualToAnchor:tcpLaneTitle.leadingAnchor],
        [self.droppedLabel.centerYAnchor constraintEqualToAnchor:self.heldLabel.centerYAnchor],
        [self.droppedLabel.trailingAnchor constraintEqualToAnchor:netCard.trailingAnchor constant:-16],
        [self.heldLabel.bottomAnchor constraintEqualToAnchor:netCard.bottomAnchor constant:-14],

        [hudHeader.topAnchor constraintEqualToAnchor:hudCard.topAnchor constant:12],
        [hudHeader.leadingAnchor constraintEqualToAnchor:hudCard.leadingAnchor constant:16],

        [self.toggleButton.topAnchor constraintEqualToAnchor:hudHeader.bottomAnchor constant:10],
        [self.toggleButton.centerXAnchor constraintEqualToAnchor:hudCard.centerXAnchor],
        [self.toggleButton.leadingAnchor constraintGreaterThanOrEqualToAnchor:hudCard.leadingAnchor constant:16],
        [self.toggleButton.trailingAnchor constraintLessThanOrEqualToAnchor:hudCard.trailingAnchor constant:-16],
        [self.toggleButton.widthAnchor constraintLessThanOrEqualToConstant:420],
        [self.toggleButton.heightAnchor constraintEqualToConstant:42],

        [self.spawnHUDButton.topAnchor constraintEqualToAnchor:self.toggleButton.bottomAnchor constant:8],
        [self.spawnHUDButton.centerXAnchor constraintEqualToAnchor:hudCard.centerXAnchor],
        [self.spawnHUDButton.leadingAnchor constraintGreaterThanOrEqualToAnchor:hudCard.leadingAnchor constant:16],
        [self.spawnHUDButton.trailingAnchor constraintLessThanOrEqualToAnchor:hudCard.trailingAnchor constant:-16],
        [self.spawnHUDButton.widthAnchor constraintLessThanOrEqualToConstant:420],
        [self.spawnHUDButton.heightAnchor constraintEqualToConstant:44],

        [self.hudStatus.topAnchor constraintEqualToAnchor:self.spawnHUDButton.bottomAnchor constant:7],
        [self.hudStatus.centerXAnchor constraintEqualToAnchor:hudCard.centerXAnchor],

        [self.debugLabel.topAnchor constraintEqualToAnchor:self.hudStatus.bottomAnchor constant:2],
        [self.debugLabel.centerXAnchor constraintEqualToAnchor:hudCard.centerXAnchor],
        [self.debugLabel.leadingAnchor constraintGreaterThanOrEqualToAnchor:hudCard.leadingAnchor constant:12],
        [self.debugLabel.trailingAnchor constraintLessThanOrEqualToAnchor:hudCard.trailingAnchor constant:-12],

        [self.viewLogButton.topAnchor constraintEqualToAnchor:self.debugLabel.bottomAnchor constant:6],
        [self.viewLogButton.centerXAnchor constraintEqualToAnchor:hudCard.centerXAnchor],
        [self.viewLogButton.leadingAnchor constraintGreaterThanOrEqualToAnchor:hudCard.leadingAnchor constant:16],
        [self.viewLogButton.trailingAnchor constraintLessThanOrEqualToAnchor:hudCard.trailingAnchor constant:-16],
        [self.viewLogButton.widthAnchor constraintLessThanOrEqualToConstant:420],
        [self.viewLogButton.heightAnchor constraintEqualToConstant:32],
        [self.viewLogButton.bottomAnchor constraintEqualToAnchor:hudCard.bottomAnchor constant:-10],
    ]];
    [self applyPureAutoLayout];
}

- (void)applyPureAutoLayout {
    // Every descendant of the scroll view must be a pure Auto Layout participant.
    AetherDisableAutoresizingTranslates(self.scrollView);
}

- (void)syncSpawnButtonLayout {
    for (CALayer *l in self.spawnHUDButton.layer.sublayers) {
        if ([l.name isEqualToString:@"aetherPrimaryGloss"]) l.frame = self.spawnHUDButton.bounds;
    }
}

#pragma mark - Actions

- (void)openProcessPicker {
    ProcessPickerViewController *picker = [[ProcessPickerViewController alloc] init];
    picker.onProcessSelected = ^(AetherProcessInfo *info) {
        NSError *err = nil;
        BOOL ok = [[AetherProcessManager sharedManager] injectIntoProcess:info error:&err];
        AetherSharedState *state = AetherGetSharedState();
        if (ok && state) {
            [self showInjectionToast:info];
        }
        [self reloadFromSharedState];
    };
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:picker];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    nav.view.backgroundColor = [AppTheme colorObsidian];
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)showInjectionToast:(AetherProcessInfo *)info {
    AetherSharedState *state = AetherGetSharedState();
    uint8_t m = state ? aether_atomic_load(&state->injectionMethod) : 0;
    NSString *method = (m == 3) ? @"Mach dylib hooks + Dopamine PPL bypass"
                     : (m == 1) ? @"Mach dylib hooks"
                                : @"Root socket engine";
    NSString *msg = [NSString stringWithFormat:@"Injected into %@ (PID %d)\nvia %@", info.displayName, info.pid, method];
    [self showToast:msg];
}

- (void)showToast:(NSString *)msg {
    UIView *toast = [AppTheme cardContainerView];
    toast.alpha = 0.0;
    UILabel *label = [AppTheme valueLabelWithText:msg mono:NO];
    label.textColor = [AppTheme colorTextPrimary];
    label.numberOfLines = 2;
    label.textAlignment = NSTextAlignmentCenter;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    toast.translatesAutoresizingMaskIntoConstraints = NO;
    [toast addSubview:label];
    [self.view addSubview:toast];

    [NSLayoutConstraint activateConstraints:@[
        [toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [toast.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-20],
        [toast.widthAnchor constraintLessThanOrEqualToConstant:320],
        [label.topAnchor constraintEqualToAnchor:toast.topAnchor constant:12],
        [label.bottomAnchor constraintEqualToAnchor:toast.bottomAnchor constant:-12],
        [label.leadingAnchor constraintEqualToAnchor:toast.leadingAnchor constant:16],
        [label.trailingAnchor constraintEqualToAnchor:toast.trailingAnchor constant:-16],
    ]];

    [UIView animateWithDuration:0.25 animations:^{ toast.alpha = 1.0; }
        completion:^(BOOL f) {
            [UIView animateWithDuration:0.3 delay:1.8 options:UIViewAnimationOptionCurveEaseIn animations:^{
                toast.alpha = 0.0;
            } completion:^(BOOL f2) { [toast removeFromSuperview]; }];
        }];
}

- (void)toggleInterceptionTapped {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;
    BOOL cur = aether_atomic_load(&state->interceptionActive);
    AetherLog(@"user tapped toggle -> %@", !cur ? @"START" : @"STOP");
    [[AetherProcessManager sharedManager] setInterceptionActive:!cur];
    if (aether_atomic_load(&state->floatingHapticEnabled)) {
        UIImpactFeedbackGenerator *fb = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
        [fb impactOccurred];
    }
    [self reloadFromSharedState];
}

- (void)viewLogTapped {
    NSString *path = AetherLogAppPath();
    NSString *content = path ? [NSString stringWithContentsOfFile:path
                                                        encoding:NSUTF8StringEncoding
                                                           error:nil] : nil;
    if (!content.length) content = @"(log trống — chưa có sự kiện nào được ghi)";

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [AppTheme colorObsidian];
    vc.title = @"aethernet.log";

    UITextView *tv = [[UITextView alloc] init];
    tv.translatesAutoresizingMaskIntoConstraints = NO;
    tv.editable = NO;
    tv.showsVerticalScrollIndicator = YES;
    tv.backgroundColor = [UIColor clearColor];
    tv.textColor = [AppTheme colorTextPrimary];
    tv.font = [AppTheme monoFont:10.0];
    tv.text = content;
    // Auto-scroll to bottom so latest entries are visible
    [tv scrollRangeToVisible:NSMakeRange(content.length, 0)];
    [vc.view addSubview:tv];
    [NSLayoutConstraint activateConstraints:@[
        [tv.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor constant:8],
        [tv.bottomAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.bottomAnchor constant:-8],
        [tv.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:12],
        [tv.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-12],
    ]];

    UIBarButtonItem *share = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                                                                           target:self
                                                                           action:@selector(shareLogTapped)];
    vc.navigationItem.rightBarButtonItem = share;

    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.navigationBar.barTintColor = [AppTheme colorObsidian];
    nav.navigationBar.translucent = NO;
    nav.navigationBar.titleTextAttributes = @{NSForegroundColorAttributeName: [AppTheme colorTextPrimary]};

    // Auto-refresh log content every 1.5s while the viewer is visible.
    // Merges daemon log so injected-payload logs surface in real time,
    // then auto-scrolls to the bottom.
    __weak UITextView *weakTV = tv;
    NSTimer *refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.5
                                                             repeats:YES
                                                               block:^(NSTimer *timer) {
        AetherLogMergeDaemonLog();
        NSString *p = AetherLogAppPath();
        NSString *c = p ? [NSString stringWithContentsOfFile:p
                                                    encoding:NSUTF8StringEncoding
                                                       error:nil] : nil;
        if (c.length > 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                __strong UITextView *strongTV = weakTV;
                if (strongTV) {
                    strongTV.text = c;
                    [strongTV scrollRangeToVisible:NSMakeRange(c.length, 0)];
                }
            });
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:refreshTimer forMode:NSRunLoopCommonModes];

    [self presentViewController:nav animated:YES completion:^{
        [refreshTimer invalidate];
    }];
}

- (void)shareLogTapped {
    NSString *path = AetherLogAppPath();
    if (!path) return;
    UIActivityViewController *avc = [[UIActivityViewController alloc]
                                     initWithActivityItems:@[[NSURL fileURLWithPath:path]]
                                     applicationActivities:nil];
    [self presentViewController:avc animated:YES completion:nil];
}

- (void)spawnHUDTapped {
    AetherLog(@"user tapped Create/Remove Floating Button");
    AetherProcessManager *pm = [AetherProcessManager sharedManager];
    BOOL running = [pm isGlobalFloatingHUDRunning];
    [pm setGlobalFloatingHUDEnabled:!running];
    [self reloadFromSharedState];

    // Verify the HUD daemon actually came up and tell the user
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL nowRunning = [[AetherProcessManager sharedManager] isGlobalFloatingHUDRunning];
        if (nowRunning) {
            [strongSelf showToast: running
                ? @"Floating button removed"
                : @"Floating button spawned · root HUD daemon is live"];
        } else if (!running) {
            [strongSelf showToast:@"HUD daemon failed to start — check TrollStore entitlements and retry"];
        }
        [strongSelf reloadFromSharedState];
    });
}

#pragma mark - Live Telemetry Ticker

- (void)startTicker {
    __weak typeof(self) weakSelf = self;
    self.ticker = [NSTimer timerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [weakSelf reloadFromSharedState];
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.ticker forMode:NSRunLoopCommonModes];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadFromSharedState];
}

- (void)dealloc {
    [self.ticker invalidate];
}

static NSString * FormatRate(uint32_t bytesPerSec) {
    if (bytesPerSec >= 1048576) return [NSString stringWithFormat:@"%.1f MB/s", bytesPerSec / 1048576.0];
    if (bytesPerSec >= 1024)    return [NSString stringWithFormat:@"%.1f KB/s", bytesPerSec / 1024.0];
    return [NSString stringWithFormat:@"%u B/s", bytesPerSec];
}

- (void)reloadFromSharedState {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self reloadFromSharedState]; });
        return;
    }
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    pid_t pid = aether_atomic_load(&state->targetPID);
    BOOL injected = aether_atomic_load(&state->isInjected);

    if (pid > 0 && injected) {
        NSString *name = [NSString stringWithUTF8String:state->targetProcessName];
        self.boxTitle.text = name ?: @"Unknown process";
        self.boxSubtitle.text = [NSString stringWithFormat:@"PID %d · %@",
            pid,
            [NSString stringWithUTF8String:state->targetBundleID]];
        self.boxIcon.hidden = NO;
        self.boxIcon.image = [UIImage _applicationIconImageForBundleIdentifier:
            [NSString stringWithUTF8String:state->targetBundleID] format:0 scale:2.0]
            ?: self.boxIcon.image;

        uint8_t method = aether_atomic_load(&state->injectionMethod);
        if (method == 3) {
            self.injectPill.text = @"  INJECTED · DYLIB HOOKS + PPL BYPASS (DOPAMINE)  ";
            self.injectPill.backgroundColor = [[AppTheme colorGold] colorWithAlphaComponent:0.16];
            self.injectPill.textColor = [AppTheme colorGold];
        } else {
            self.injectPill.text = (method == 1) ? @"  INJECTED · DYLIB HOOKS  " : @"  ATTACHED · ROOT ENGINE  ";
        }
        self.injectPill.backgroundColor = [[AppTheme colorActiveGreen] colorWithAlphaComponent:0.16];
        self.injectPill.textColor = [AppTheme colorActiveGreen];
        self.targetBox.layer.borderColor = [[AppTheme colorActiveGreen] colorWithAlphaComponent:0.45].CGColor;
    } else {
        self.boxTitle.text = @"Tap to select process";
        self.boxSubtitle.text = @"Choose the PID to inject libNetHookPayload.dylib";
        self.boxIcon.hidden = YES;
        self.injectPill.text = @"  NOT INJECTED  ";
        self.injectPill.backgroundColor = [[AppTheme colorWarnRed] colorWithAlphaComponent:0.12];
        self.injectPill.textColor = [AppTheme colorWarnRed];
        self.targetBox.layer.borderColor = [[AppTheme colorGoldMuted] colorWithAlphaComponent:0.35].CGColor;
    }

    uint32_t tcp = aether_atomic_load(&state->activeTCPSockets);
    uint32_t udp = aether_atomic_load(&state->activeUDPSockets);
    uint64_t tcpRX = aether_atomic_load(&state->totalTCPPacketsRX);
    uint64_t tcpTX = aether_atomic_load(&state->totalTCPPacketsTX);
    uint64_t udpRX = aether_atomic_load(&state->totalUDPPacketsRX);
    uint64_t udpTX = aether_atomic_load(&state->totalUDPPacketsTX);
    uint32_t rxRate = aether_atomic_load(&state->currentRXRateBps);
    uint32_t txRate = aether_atomic_load(&state->currentTXRateBps);

    self.tcpStatLabel.text = [NSString stringWithFormat:@"%u sockets · ↓%llu ↑%llu pkts", tcp, tcpRX, tcpTX];
    self.udpStatLabel.text = [NSString stringWithFormat:@"%u sockets · ↓%llu ↑%llu pkts", udp, udpRX, udpTX];
    self.tcpRateLabel.text = [NSString stringWithFormat:@"↓ %@ · ↑ %@", FormatRate(rxRate), FormatRate(txRate)];
    self.udpRateLabel.text = [NSString stringWithFormat:@"↓ %@ · ↑ %@", FormatRate(rxRate), FormatRate(txRate)];

    uint8_t dir = aether_atomic_load(&state->direction);
    uint8_t mode = aether_atomic_load(&state->interceptMode);
    NSString *dirStr = (dir == AetherDirectionDownload) ? @"Download only" :
                       (dir == AetherDirectionUpload) ? @"Upload only" : @"Both directions";
    NSString *modeStr = (mode == AetherModeHoldQueue) ? @"Hold Queue" :
                        (mode == AetherModeDropPacket) ? @"Drop" :
                        (mode == AetherModeDelayJitter) ? @"Delay + Jitter" : @"Tamper";
    BOOL interceptingNow = aether_atomic_load(&state->interceptionActive);
    uint8_t injMethod = aether_atomic_load(&state->injectionMethod);
    NSString *engineStr = @"";
    if (interceptingNow) {
        engineStr = (injMethod == 2) ? @" · capture ON (hook payload)" : @" · ⏸ HOLDING";
    }
    self.modeLabel.text = [NSString stringWithFormat:@"Mode: %@ · %@%@", modeStr, dirStr, engineStr];

    self.heldLabel.text = [NSString stringWithFormat:@"Held: %llu pkts", aether_atomic_load(&state->heldPacketsCount)];
    self.droppedLabel.text = [NSString stringWithFormat:@"Dropped: %llu pkts", aether_atomic_load(&state->droppedPacketsCount)];

    BOOL hudRunning = [[AetherProcessManager sharedManager] isGlobalFloatingHUDRunning];
    BOOL intercepting = aether_atomic_load(&state->interceptionActive);
    self.hudStatus.text = hudRunning
        ? (intercepting ? @"HUD daemon: running · intercepting ⏸"
                        : @"HUD daemon: running · standby ▶")
        : @"HUD daemon: offline";
    NSString *toggleTitle = intercepting ? @"⏸ Stop intercepting" : @"▶ Start intercepting";
    if (![self.toggleButton.buttonLabel.text isEqualToString:toggleTitle]) {
        self.toggleButton.buttonLabel.text = toggleTitle;
    }
    self.debugLabel.numberOfLines = 2;
    self.debugLabel.text = [NSString stringWithFormat:
        @"cb:%u dig:%u began:%u hit:%u del:%u ready:%u\n"
        @"raw:%u,%u max:%u,%u T:%u win:%ux%u btn:%u,%u",
        aether_atomic_load(&state->dbgCallbackCount),
        aether_atomic_load(&state->dbgDigCount),
        aether_atomic_load(&state->dbgBeganCount),
        aether_atomic_load(&state->dbgHitCount),
        aether_atomic_load(&state->dbgDeliveredCount),
        aether_atomic_load(&state->dbgRawReady),
        aether_atomic_load(&state->dbgLastX),
        aether_atomic_load(&state->dbgLastY),
        aether_atomic_load(&state->dbgMaxX),
        aether_atomic_load(&state->dbgMaxY),
        aether_atomic_load(&state->dbgScale),
        aether_atomic_load(&state->dbgWinW),
        aether_atomic_load(&state->dbgWinH),
        aether_atomic_load(&state->dbgBtnX),
        aether_atomic_load(&state->dbgBtnY)];

    // Transition-only title mutation: mutating UIButton title on every ticker
    // tick is a known KVO crash trigger (UIButtonLegacyVisualProvider _updateTitleView)
    if (hudRunning != _lastHUDRunningState || self.spawnHUDButton.buttonLabel.text.length == 0) {
        self.spawnHUDButton.buttonLabel.text = hudRunning ? @"Remove Floating Button" : @"Create Floating Button";
        _lastHUDRunningState = hudRunning;
    }
}

@end
