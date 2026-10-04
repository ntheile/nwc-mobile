#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
NS_ASSUME_NONNULL_BEGIN
/** Native registration only. The implementation calls Rust's restricted dispatcher. */
@protocol NwcMobileHost <NSObject>
- (void)dispatchWallet:(NSString *)walletId request:(NSString *)request
              resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
@end
@interface NwcMobileHostRegistry : NSObject
+ (BOOL)registerHost:(id<NwcMobileHost>)host NS_SWIFT_NAME(registerHost(_:));
@end
NS_ASSUME_NONNULL_END
