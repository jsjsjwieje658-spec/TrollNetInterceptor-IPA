//
//  LogViewController.mm
//  AetherNet — Tab 3: Log Viewer
//
//  Full-screen log viewer with auto-refresh, auto-scroll, copy-all,
//  and share buttons. Pulls from the merged app log that includes
//  daemon-side entries (HUD touch events, hook payload logs).
//

#import "LogViewController.h"
#import "AppTheme.h"
#import "../Core/AetherLog.h"
#import "../headers/AetherNetShared.h"

@interface LogViewController () {
    UITextView *_tv;
    NSTimer *_refreshTimer;
    NSString *_lastContent;
    UIButton *_copyBtn;
    UIButton *_shareBtn;
    UIButton *_clearBtn;
}
@end

@implementation LogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [AppTheme colorObsidian];
    self.title = @"Log Viewer";

    // --- Toolbar ---
    UIView *toolbar = [[UIView alloc] init];
    toolbar.backgroundColor = [[AppTheme colorElevated] colorWithAlphaComponent:0.85];
    toolbar.layer.borderColor = [AppTheme colorCardBorder].CGColor;
    toolbar.layer.borderWidth = 1.0 / [UIScreen mainScreen].scale;
    toolbar.layer.cornerRadius = 8;
    toolbar.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:toolbar];

    _copyBtn = [self makeToolButton:@"Copy All" action:@selector(copyAllTapped)];
    _shareBtn = [self makeToolButton:@"Share" action:@selector(shareTapped)];
    _clearBtn = [self makeToolButton:@"Clear" action:@selector(clearTapped)];

    [toolbar addSubview:_copyBtn];
    [toolbar addSubview:_shareBtn];
    [toolbar addSubview:_clearBtn];

    [NSLayoutConstraint activateConstraints:@[
        [toolbar.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12],
        [toolbar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [toolbar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [toolbar.heightAnchor constraintEqualToConstant:44],

        [_copyBtn.topAnchor constraintEqualToAnchor:toolbar.topAnchor constant:4],
        [_copyBtn.bottomAnchor constraintEqualToAnchor:toolbar.bottomAnchor constant:-4],
        [_copyBtn.leadingAnchor constraintEqualToAnchor:toolbar.leadingAnchor constant:8],

        [_clearBtn.topAnchor constraintEqualToAnchor:_copyBtn.topAnchor],
        [_clearBtn.bottomAnchor constraintEqualToAnchor:_copyBtn.bottomAnchor],
        [_clearBtn.trailingAnchor constraintEqualToAnchor:toolbar.trailingAnchor constant:-8],

        [_shareBtn.centerYAnchor constraintEqualToAnchor:_copyBtn.centerYAnchor],
        [_shareBtn.leadingAnchor constraintEqualToAnchor:_copyBtn.trailingAnchor constant:12],
        [_shareBtn.trailingAnchor constraintEqualToAnchor:_clearBtn.leadingAnchor constant:-12],
    ]];

    // --- Log text view ---
    _tv = [[UITextView alloc] init];
    _tv.translatesAutoresizingMaskIntoConstraints = NO;
    _tv.editable = NO;
    _tv.showsVerticalScrollIndicator = YES;
    _tv.backgroundColor = [UIColor clearColor];
    _tv.textColor = [AppTheme colorTextPrimary];
    _tv.font = [AppTheme monoFont:10.0];
    _tv.dataDetectorTypes = UIDataDetectorTypeNone;
    [self.view addSubview:_tv];

    [NSLayoutConstraint activateConstraints:@[
        [_tv.topAnchor constraintEqualToAnchor:toolbar.bottomAnchor constant:12],
        [_tv.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-12],
        [_tv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [_tv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
    ]];

    // --- Pull to refresh (manual merge + re-read) ---
    UIRefreshControl *refresh = [[UIRefreshControl alloc] init];
    refresh.tintColor = [AppTheme colorTextSecondary];
    [refresh addTarget:self action:@selector(manualRefresh) forControlEvents:UIControlEventValueChanged];
    _tv.refreshControl = refresh;

    // --- Auto-refresh every 1.0s (fires during scroll via CommonModes) ---
    _refreshTimer = [NSTimer timerWithTimeInterval:1.0
                                           repeats:YES
                                             block:^(NSTimer *timer) {
        [self refreshLog];
    }];
    [[NSRunLoop mainRunLoop] addTimer:_refreshTimer forMode:NSRunLoopCommonModes];
}

- (UIButton *)makeToolButton:(NSString *)title action:(SEL)sel {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    [btn setTitle:title forState:UIControlStateNormal];
    [btn setTitleColor:[AppTheme colorGold] forState:UIControlStateNormal];
    btn.backgroundColor = [[AppTheme colorCardBorder] colorWithAlphaComponent:0.12];
    btn.layer.cornerRadius = 6;
    [btn setTitleEdgeInsets:UIEdgeInsetsMake(4, 10, 4, 10)];
    [btn addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    return btn;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refreshLog];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
}

- (void)manualRefresh {
    AetherLogMergeDaemonLog();
    [self refreshLog];
    if (_tv.refreshControl.isRefreshing) {
        [_tv.refreshControl endRefreshing];
    }
}

- (void)refreshLog {
    AetherLogMergeDaemonLog();
    NSString *path = AetherLogAppPath();
    NSString *content = path ? [NSString stringWithContentsOfFile:path
                                                        encoding:NSUTF8StringEncoding
                                                           error:nil] : nil;
    if (!content || content.length == 0) {
        content = @"(log trống — chưa có sự kiện nào được ghi)";
    }
    if ([content isEqualToString:_lastContent]) return;
    _lastContent = content;

    dispatch_async(dispatch_get_main_queue(), ^{
        _tv.text = content;
        [_tv scrollRangeToVisible:NSMakeRange(content.length, 0)];
    });
}

- (void)copyAllTapped {
    if (!_lastContent) {
        [self refreshLog];
    }
    if (_lastContent.length > 0) {
        UIPasteboard.generalPasteboard.string = _lastContent;
        [self showToast:@"Copied to clipboard"];
    }
}

- (void)shareTapped {
    if (!_lastContent) {
        [self refreshLog];
    }
    if (_lastContent.length > 0) {
        NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"AetherNet.log"];
        [_lastContent writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSURL *url = [NSURL fileURLWithPath:tmpPath];
        UIActivityViewController *avc = [[UIActivityViewController alloc]
            initWithActivityItems:@[url]
            applicationActivities:nil];
        [self presentViewController:avc animated:YES completion:nil];
    }
}

- (void)clearTapped {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Xóa log?"
        message:@"Xóa toàn bộ nội dung log. Hành động này không thể hoàn tác."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Xóa" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [AetherLogClear];
        [self refreshLog];
        [self showToast:@"Log cleared"];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showToast:(NSString *)msg {
    UILabel *toast = [[UILabel alloc] init];
    toast.backgroundColor = [[AppTheme colorActiveGreen] colorWithAlphaComponent:0.85];
    toast.textColor = [UIColor blackColor];
    toast.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    toast.textAlignment = NSTextAlignmentCenter;
    toast.text = msg;
    toast.layer.cornerRadius = 6;
    toast.clipsToBounds = YES;
    toast.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:toast];
    [NSLayoutConstraint activateConstraints:@[
        [toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [toast.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-30],
        [toast.heightAnchor constraintEqualToConstant:30],
        [toast.widthAnchor constraintEqualToConstant:120],
    ]];
    [UIView animateWithDuration:1.8 animations:^{
        toast.alpha = 0.0;
    } completion:^(BOOL finished) {
        [toast removeFromSuperview];
    }];
}

@end
