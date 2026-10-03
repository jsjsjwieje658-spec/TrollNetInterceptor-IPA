//
//  HomeViewController.h
//  AetherNet — Tab 1: Target Selection & Live L4 Telemetry
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface HomeViewController : UIViewController
@property (nonatomic, strong) UILabel *boxTitle;
@property (nonatomic, strong) UILabel *boxSubtitle;
- (void)reloadFromSharedState;
@end

NS_ASSUME_NONNULL_END
