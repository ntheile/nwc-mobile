// Native adapter maintained alongside the generated bindings.
#if !defined(RCT_NEW_ARCH_ENABLED) || !RCT_NEW_ARCH_ENABLED
#error "NwcMobile requires React Native New Architecture."
#else
#ifdef __cplusplus
#import "react-native-nwc-mobile.h"
#endif

#import "NwcMobileSpec.h"

@interface NwcMobile : NSObject <NativeNwcMobileSpec>

@end
#endif
