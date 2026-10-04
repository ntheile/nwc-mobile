#import "NwcMobile.h"

static id<NwcMobileHost> nativeHost;
@implementation NwcMobileHostRegistry

+ (BOOL)registerHost:(id<NwcMobileHost>)host {
  @synchronized(self) {
    if (nativeHost != nil) return nativeHost == host;
    nativeHost = host;
    return YES;
  }
}

@end

@implementation NwcMobile
RCT_EXPORT_MODULE()
- (void)dispatch:(NSString *)walletId
        request:(NSString *)request
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject {
  if (walletId.length == 0 || walletId.length > 256 || request.length > 131072) {
    reject(@"InvalidArgument", @"Invalid NWC request", nil);
    return;
  }
  id<NwcMobileHost> host;
  @synchronized([NwcMobileHostRegistry class]) { host = nativeHost; }
  if (host == nil) {
    reject(@"NotReady", @"Native NWC host is not registered", nil);
    return;
  }
  [host dispatchWallet:walletId request:request resolve:resolve reject:reject];
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params {
  return std::make_shared<facebook::react::NativeNwcMobileSpecJSI>(params);
}
@end
