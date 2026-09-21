import { statSync } from 'node:fs';
const required = [
  'src/generated/nwc_mobile_uniffi.ts',
  'cpp/generated/nwc_mobile_uniffi.cpp',
  'cpp/generated/nwc_mobile_uniffi.hpp',
  'native/swift/NwcMobile.swift',
  'native/swift/NwcMobileFFI.h',
  'native/kotlin/org/nwc/mobile/nwc_mobile_uniffi.kt',
  'NwcMobileFramework.xcframework/Info.plist',
  'NwcMobileFramework.xcframework/ios-arm64/libnwc_mobile_uniffi.a',
  'NwcMobileFramework.xcframework/ios-arm64-simulator/libnwc_mobile_uniffi.a',
  'android/src/main/jniLibs/arm64-v8a/libnwc_mobile_uniffi.so',
  'android/generated/java/com/nwcmobile/reactnative/NativeNwcMobileSpec.java',
  'ios/generated/NwcMobileSpec/NwcMobileSpec.h',
  'lib/index.js',
  'lib/index.d.ts',
];
for (const file of required) {
  if (!statSync(file, { throwIfNoEntry: false })?.size) {
    throw new Error(`Missing native/package artifact: ${file}. Build and verify native libraries before packing.`);
  }
}
