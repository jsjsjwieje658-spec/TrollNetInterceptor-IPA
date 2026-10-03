//
//  HomeViewController.mm
//  AetherNet — Tab 1: Home (Clean & Simple)
//

#import "HomeViewController.h"
#import "AppTheme.h"
#import "AetherGoldButton.h"
#import "../Core/AetherLog.h"
#import "../Core/ProcessManager.h"
#import "../headers/AetherNetShared.h"
#include <notify.h>

#pragma mark - Process Picker

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
    UILabel *subtitle = [AppTheme valueLabelWithText:@"Choose a running PID to intercept TCP/UDP traffic" mono:NO];

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

    UIBarButtonItem *refresh = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                                             target:self action:@selector(refreshTapped)];
    refresh.tintColor = [AppTheme colorGold];
    self.navigationItem.leftBarButtonItem = refresh;

    UIRefreshControl *refreshControl = [[UIRefreshControl alloc] init];
    refreshControl.tintColor = [AppTheme colorGold];
    [refreshControl addTarget:self action:@selector(refreshTapped) forControlEvents:UIControlEventValueChanged];
    _table.refreshControl = refreshControl;
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

- (void)scopeChanged { [self reloadData]; }

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

- (void)dismissTapped { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)refreshTapped {
    [_table.refreshControl endRefreshing];
    [self reloadData];
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
            [card.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:12],
            [card.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-12],
            [card.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-5],

            [iconHost.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
            [iconHost.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
            [iconHost.widthAnchor constraintEqualToConstant:size],
            [iconHost.heightAnchor constraintEqualToConstant:size],

            [name.leadingAnchor constraintEqualToAnchor:iconHost.trailingAnchor constant:12],
            [name.topAnchor constraintEqualToAnchor:card.topAnchor constant:12],
            [name.trailingAnchor constraintLessThanOrEqualToAnchor:socketBadge.leadingAnchor constant:-8],

            [detail.leadingAnchor constraintEqualToAnchor:name.leadingAnchor],
            [detail.topAnchor constraintEqualToAnchor:name.bottomAnchor constant:2],
            [detail.trailingAnchor constraintLessThanOrEqualToAnchor:card.trailingAnchor constant:-12],

            [socketBadge.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-12],
            [socketBadge.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
            [socketBadge.widthAnchor constraintEqualToConstant:80],
        ]];
    }

    if (info.appIcon) {
        UIImageView *iv = [[UIImageView alloc] initWithImage:info.appIcon];
        iv.frame = iconHost.bounds;
        iv.contentMode = UIViewContentModeScaleAspectFit;
        [iconHost.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
        [iconHost addSubview:iv];
    } else {
        UILabel *placeholder = [[UILabel alloc] initWithFrame:iconHost.bounds];
        placeholder.text = [info.displayName substringToIndex:1].uppercaseString;
        placeholder.font = [AppTheme displayFont:20];
        placeholder.textAlignment = NSTextAlignmentCenter;
        placeholder.textColor = [AppTheme colorGold];
        placeholder.backgroundColor = [AppTheme colorElevated];
        [iconHost.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
        [iconHost addSubview:placeholder];
    }

    name.text = info.displayName;
    detail.text = [NSString stringWithFormat:@"PID %d  •  %@", info.pid, info.bundleIdentifier];
    
    uint32_t totalSockets = info.tcpSocketCount + info.udpSocketCount;
    if (totalSockets > 0) {
        socketBadge.text = [NSString stringWithFormat:@"TCP:%u UDP:%u", info.tcpSocketCount, info.udpSocketCount];
        socketBadge.textColor = [AppTheme colorGold];
    } else {
        socketBadge.text = @"no sockets";
        socketBadge.textColor = [AppTheme colorTextSecondary];
    }

    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    AetherProcessInfo *info = _visibleProcesses[indexPath.row];
    if (self.onProcessSelected) self.onProcessSelected(info);
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end

#pragma mark - HomeViewController

@interface HomeViewController ()
@property (nonatomic, strong) UIButton *targetBox;
@property (nonatomic, strong) AetherGoldButton *interceptButton;
@property (nonatomic, strong) AetherGoldButton *spawnHUDButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *brandLabel;
@end

@implementation HomeViewController {
    UIScrollView *_scrollView;
    UIView *_contentView;
    NSTimer *_refreshTimer;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [AppTheme colorObsidian];
    self.title = @"AetherNet";

    _scrollView = [[UIScrollView alloc] init];
    _scrollView.showsVerticalScrollIndicator = NO;
    _scrollView.alwaysBounceVertical = YES;
    [self.view addSubview:_scrollView];

    _contentView = [[UIView alloc] init];
    [_scrollView addSubview:_contentView];

    _scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    _contentView.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [_scrollView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [_scrollView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_scrollView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [_contentView.topAnchor constraintEqualToAnchor:_scrollView.topAnchor],
        [_contentView.leadingAnchor constraintEqualToAnchor:_scrollView.leadingAnchor],
        [_contentView.trailingAnchor constraintEqualToAnchor:_scrollView.trailingAnchor],
        [_contentView.bottomAnchor constraintEqualToAnchor:_scrollView.bottomAnchor],
        [_contentView.widthAnchor constraintEqualToAnchor:_scrollView.widthAnchor],
    ]];

    [self setupBrandHeader];
    [self setupTargetCard];
    [self setupInterceptCard];
    [self setupHUDCard];

    [self reloadFromSharedState];

    _refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.5
                                                      target:self
                                                    selector:@selector(reloadFromSharedState)
                                                    userInfo:nil
                                                     repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:_refreshTimer forMode:NSRunLoopCommonModes];
}

- (void)setupBrandHeader {
    self.brandLabel = [AppTheme titleLabelWithText:@"AetherNet"];
    self.brandLabel.font = [AppTheme displayFont:28];
    self.brandLabel.textAlignment = NSTextAlignmentCenter;

    UILabel *subtitle = [AppTheme valueLabelWithText:@"TCP/UDP Packet Interception" mono:NO];
    subtitle.textAlignment = NSTextAlignmentCenter;

    [_contentView addSubview:self.brandLabel];
    [_contentView addSubview:subtitle];

    self.brandLabel.translatesAutoresizingMaskIntoConstraints = NO;
    subtitle.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [self.brandLabel.topAnchor constraintEqualToAnchor:_contentView.topAnchor constant:24],
        [self.brandLabel.leadingAnchor constraintEqualToAnchor:_contentView.leadingAnchor constant:24],
        [self.brandLabel.trailingAnchor constraintEqualToAnchor:_contentView.trailingAnchor constant:-24],

        [subtitle.topAnchor constraintEqualToAnchor:self.brandLabel.bottomAnchor constant:4],
        [subtitle.leadingAnchor constraintEqualToAnchor:self.brandLabel.leadingAnchor],
        [subtitle.trailingAnchor constraintEqualToAnchor:self.brandLabel.trailingAnchor],
    ]];
}

- (void)setupTargetCard {
    UIView *card = [AppTheme cardContainerView];
    [_contentView addSubview:card];

    UILabel *header = [AppTheme titleLabelWithText:@"Target Process"];
    [_contentView addSubview:header];

    self.targetBox = [UIButton buttonWithType:UIButtonTypeCustom];
    [self.targetBox addTarget:self action:@selector(openProcessPicker) forControlEvents:UIControlEventTouchUpInside];
    self.targetBox.backgroundColor = [AppTheme colorElevated];
    self.targetBox.layer.cornerRadius = 14;
    self.targetBox.layer.borderWidth = 1;
    self.targetBox.layer.borderColor = [AppTheme colorCardBorder].CGColor;
    self.targetBox.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    [card addSubview:self.targetBox];

    UIView *boxIcon = [[UIView alloc] init];
    boxIcon.layer.cornerRadius = 11;
    boxIcon.clipsToBounds = YES;
    boxIcon.backgroundColor = [AppTheme colorObsidian];
    [self.targetBox addSubview:boxIcon];

    self.boxTitle = [AppTheme titleLabelWithText:@""];
    self.boxTitle.font = [AppTheme displayFont:15];
    [self.targetBox addSubview:self.boxTitle];

    self.boxSubtitle = [AppTheme valueLabelWithText:@"" mono:NO];
    [self.targetBox addSubview:self.boxSubtitle];

    header.translatesAutoresizingMaskIntoConstraints = NO;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    self.targetBox.translatesAutoresizingMaskIntoConstraints = NO;
    boxIcon.translatesAutoresizingMaskIntoConstraints = NO;
    self.boxTitle.translatesAutoresizingMaskIntoConstraints = NO;
    self.boxSubtitle.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:self.brandLabel.bottomAnchor constant:24],
        [card.leadingAnchor constraintEqualToAnchor:_contentView.leadingAnchor constant:16],
        [card.trailingAnchor constraintEqualToAnchor:_contentView.trailingAnchor constant:-16],

        [header.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [self.targetBox.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:10],
        [self.targetBox.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:14],
        [self.targetBox.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [self.targetBox.heightAnchor constraintEqualToConstant:92],
        [self.targetBox.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],

        [boxIcon.leadingAnchor constraintEqualToAnchor:self.targetBox.leadingAnchor constant:16],
        [boxIcon.centerYAnchor constraintEqualToAnchor:self.targetBox.centerYAnchor],
        [boxIcon.widthAnchor constraintEqualToConstant:48],
        [boxIcon.heightAnchor constraintEqualToConstant:48],

        [self.boxTitle.topAnchor constraintEqualToAnchor:self.targetBox.topAnchor constant:14],
        [self.boxTitle.leadingAnchor constraintEqualToAnchor:boxIcon.trailingAnchor constant:14],
        [self.boxTitle.trailingAnchor constraintEqualToAnchor:self.targetBox.trailingAnchor constant:-14],

        [self.boxSubtitle.topAnchor constraintEqualToAnchor:self.boxTitle.bottomAnchor constant:4],
        [self.boxSubtitle.leadingAnchor constraintEqualToAnchor:self.boxTitle.leadingAnchor],
        [self.boxSubtitle.trailingAnchor constraintEqualToAnchor:self.targetBox.trailingAnchor constant:-14],
    ]];
}

- (void)setupInterceptCard {
    UIView *card = [AppTheme cardContainerView];
    [_contentView addSubview:card];

    UILabel *header = [AppTheme titleLabelWithText:@"Interception"];
    [_contentView addSubview:header];

    self.interceptButton = [[AetherGoldButton alloc] initWithTitle:@"▶  Start Capture"];
    [self.interceptButton addTarget:self action:@selector(toggleInterception) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:self.interceptButton];

    header.translatesAutoresizingMaskIntoConstraints = NO;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    self.interceptButton.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:self.targetBox.superview.bottomAnchor constant:16],
        [card.leadingAnchor constraintEqualToAnchor:_contentView.leadingAnchor constant:16],
        [card.trailingAnchor constraintEqualToAnchor:_contentView.trailingAnchor constant:-16],

        [header.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [self.interceptButton.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:12],
        [self.interceptButton.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [self.interceptButton.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [self.interceptButton.heightAnchor constraintEqualToConstant:50],
        [self.interceptButton.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-16],
    ]];
}

- (void)setupHUDCard {
    UIView *card = [AppTheme cardContainerView];
    [_contentView addSubview:card];

    UILabel *header = [AppTheme titleLabelWithText:@"Floating HUD Button"];
    [_contentView addSubview:header];

    self.spawnHUDButton = [[AetherGoldButton alloc] initWithTitle:@"+  Create Floating Button"];
    [self.spawnHUDButton addTarget:self action:@selector(toggleHUD) forControlEvents:UIControlEventTouchUpInside];
    [self.spawnHUDButton applySecondaryStyle];
    [card addSubview:self.spawnHUDButton];

    self.statusLabel = [AppTheme valueLabelWithText:@"" mono:NO];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    [card addSubview:self.statusLabel];

    header.translatesAutoresizingMaskIntoConstraints = NO;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    self.spawnHUDButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:self.interceptButton.superview.bottomAnchor constant:16],
        [card.leadingAnchor constraintEqualToAnchor:_contentView.leadingAnchor constant:16],
        [card.trailingAnchor constraintEqualToAnchor:_contentView.trailingAnchor constant:-16],
        [card.bottomAnchor constraintEqualToAnchor:_contentView.bottomAnchor constant:-30],

        [header.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [self.spawnHUDButton.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:12],
        [self.spawnHUDButton.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [self.spawnHUDButton.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [self.spawnHUDButton.heightAnchor constraintEqualToConstant:44],

        [self.statusLabel.topAnchor constraintEqualToAnchor:self.spawnHUDButton.bottomAnchor constant:8],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-12],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
    ]];
}

- (void)dealloc {
    [_refreshTimer invalidate];
    _refreshTimer = nil;
}

- (void)openProcessPicker {
    ProcessPickerViewController *picker = [[ProcessPickerViewController alloc] init];
    picker.onProcessSelected = ^(AetherProcessInfo *info) {
        NSError *err = nil;
        BOOL ok = [[AetherProcessManager sharedManager] injectIntoProcess:info error:&err];
        if (ok) {
            [self showToast:[NSString stringWithFormat:@"Injected into %@ (PID %d)", info.displayName, info.pid]];
        }
        [self reloadFromSharedState];
    };
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:picker];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    nav.view.backgroundColor = [AppTheme colorObsidian];
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)toggleInterception {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    BOOL currentlyActive = aether_atomic_load(&state->interceptionActive);
    pid_t targetPID = aether_atomic_load(&state->targetPID);

    if (!currentlyActive && targetPID == 0) {
        [self showToast:@"Select a target process first"];
        return;
    }

    [[AetherProcessManager sharedManager] setInterceptionActive:!currentlyActive];
    [self reloadFromSharedState];
}

- (void)toggleHUD {
    [[AetherProcessManager sharedManager] setGlobalFloatingHUDEnabled:![[AetherProcessManager sharedManager] isGlobalFloatingHUDRunning]];
    [self reloadFromSharedState];
}

- (void)reloadFromSharedState {
    AetherSharedState *state = AetherGetSharedState();
    if (!state) return;

    BOOL active = aether_atomic_load(&state->interceptionActive);
    pid_t targetPID = aether_atomic_load(&state->targetPID);
    uint8_t method = aether_atomic_load(&state->injectionMethod);

    // Update target box
    if (targetPID > 0) {
        NSArray *processes = [[AetherProcessManager sharedManager] enumerateRunningProcessesWithFilter:[NSString stringWithFormat:@"%d", targetPID] onlyUserApps:NO];
        AetherProcessInfo *info = processes.firstObject;
        if (info) {
            self.boxTitle.text = info.displayName;
            self.boxSubtitle.text = [NSString stringWithFormat:@"PID %d  •  %@  •  TCP:%u UDP:%u",
                                     info.pid, info.bundleIdentifier, info.tcpSocketCount, info.udpSocketCount];
            if (info.appIcon) {
                UIImageView *iv = [[UIImageView alloc] initWithImage:info.appIcon];
                iv.frame = self.targetBox.subviews.firstObject.bounds;
                iv.contentMode = UIViewContentModeScaleAspectFit;
                [self.targetBox.subviews.firstObject.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
                [self.targetBox.subviews.firstObject addSubview:iv];
            }
        } else {
            self.boxTitle.text = [NSString stringWithFormat:@"PID %d", targetPID];
            self.boxSubtitle.text = @"Process not found";
        }
    } else {
        self.boxTitle.text = @"Tap to select target process";
        self.boxSubtitle.text = @"Choose an app to intercept its TCP/UDP traffic";
    }

    // Update intercept button
    if (active) {
        [self.interceptButton.buttonLabel setText:@"⏸  Stop Capture"];
        self.interceptButton.backgroundColor = [AppTheme colorWarnRed];
    } else {
        [self.interceptButton.buttonLabel setText:@"▶  Start Capture"];
        self.interceptButton.backgroundColor = [AppTheme colorGold];
    }

    // Update HUD button
    BOOL hudRunning = [[AetherProcessManager sharedManager] isGlobalFloatingHUDRunning];
    [self.spawnHUDButton.buttonLabel setText:hudRunning ? @"−  Remove Floating Button" : @"+  Create Floating Button"
                            forState:UIControlStateNormal];

    // Status label
    NSString *methodStr = (method == 1) ? @"Mach dylib hooks" :
                         (method == 4) ? @"NECP + Root PF" :
                         (method == 0) ? @"NECP only" : @"Root PF only";
    self.statusLabel.text = [NSString stringWithFormat:@"Status: %@  •  Mode: %@",
                             active ? @"Capturing" : @"Idle", methodStr];
}

- (void)showToast:(NSString *)msg {
    UIView *toast = [AppTheme cardContainerView];
    toast.alpha = 0.0;
    UILabel *label = [AppTheme valueLabelWithText:msg mono:NO];
    label.textColor = [AppTheme colorTextPrimary];
    label.numberOfLines = 2;
    label.textAlignment = NSTextAlignmentCenter;
    [toast addSubview:label];
    [self.view addSubview:toast];

    toast.translatesAutoresizingMaskIntoConstraints = NO;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [NSLayoutConstraint activateConstraints:@[
        [toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [toast.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-40],
        [label.leadingAnchor constraintEqualToAnchor:toast.leadingAnchor constant:20],
        [label.trailingAnchor constraintEqualToAnchor:toast.trailingAnchor constant:-20],
        [label.topAnchor constraintEqualToAnchor:toast.topAnchor constant:14],
        [label.bottomAnchor constraintEqualToAnchor:toast.bottomAnchor constant:-14],
    ]];

    [UIView animateWithDuration:0.2 animations:^{ toast.alpha = 1.0; }
                     completion:^(BOOL f) {
                         [UIView animateWithDuration:0.2 delay:2.0 options:0 animations:^{ toast.alpha = 0.0; }
                                         completion:^(BOOL f) { [toast removeFromSuperview]; }];
                     }];
}

@end
