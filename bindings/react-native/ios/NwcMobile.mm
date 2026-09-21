// Native adapter maintained alongside the generated bindings.
#import "NwcMobile.h"

#if defined(RCT_NEW_ARCH_ENABLED) && RCT_NEW_ARCH_ENABLED
namespace uniffi_generated {
    using namespace facebook::react;
    /**
    * ObjC++ class for module 'NativeNwcMobile'
    */
    class JSI_EXPORT NativeNwcMobileSpecJSI : public ObjCTurboModule {
    public:
        NativeNwcMobileSpecJSI(const ObjCTurboModule::InitParams &params);
        std::shared_ptr<CallInvoker> callInvoker;
    };

    static facebook::jsi::Value __hostFunction_NwcMobile_installRustCrate(facebook::jsi::Runtime& rt, TurboModule &turboModule, const facebook::jsi::Value* args, size_t count) {
        auto& tm = static_cast<NativeNwcMobileSpecJSI&>(turboModule);
        auto jsInvoker = tm.callInvoker;
        uint8_t result = nwcmobile::installRustCrate(rt, jsInvoker);
        return facebook::jsi::Value(result != 0);
    }
    static facebook::jsi::Value __hostFunction_NwcMobile_cleanupRustCrate(facebook::jsi::Runtime& rt, TurboModule &turboModule, const facebook::jsi::Value* args, size_t count) {
        uint8_t result = nwcmobile::cleanupRustCrate(rt);
        return facebook::jsi::Value(result != 0);
    }

    NativeNwcMobileSpecJSI::NativeNwcMobileSpecJSI(const ObjCTurboModule::InitParams &params)
        : ObjCTurboModule(params), callInvoker(params.jsInvoker) {
            this->methodMap_["installRustCrate"] = MethodMetadata {1, __hostFunction_NwcMobile_installRustCrate};
            this->methodMap_["cleanupRustCrate"] = MethodMetadata {1, __hostFunction_NwcMobile_cleanupRustCrate};
    }
} // namespace uniffi_generated

@implementation NwcMobile
RCT_EXPORT_MODULE()

- (NSNumber *)installRustCrate {
    @throw [NSException exceptionWithName:@"UnreachableException"
                        reason:@"This method should never be called."
                        userInfo:nil];
}

- (NSNumber *)cleanupRustCrate {
    @throw [NSException exceptionWithName:@"UnreachableException"
                        reason:@"This method should never be called."
                        userInfo:nil];
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<uniffi_generated::NativeNwcMobileSpecJSI>(params);
}
@end
#endif
