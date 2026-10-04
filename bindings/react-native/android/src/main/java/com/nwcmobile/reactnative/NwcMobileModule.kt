package com.nwcmobile.reactnative

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule

/** Native bootstrap owns the implementation; JS never receives its handle. */
fun interface NwcMobileHost {
  fun dispatch(walletId: String, request: String, resolve: (String) -> Unit, reject: () -> Unit)
}

@ReactModule(name = NwcMobileModule.NAME)
class NwcMobileModule(reactContext: ReactApplicationContext) : NativeNwcMobileSpec(reactContext) {
  override fun getName() = NAME

  override fun dispatch(walletId: String, request: String, promise: Promise) {
    if (walletId.isEmpty() || walletId.length > 256 || request.length > 131072) {
      promise.reject("InvalidArgument", "Invalid NWC request")
      return
    }
    val host = nativeHost
    if (host == null) {
      promise.reject("NotReady", "Native NWC host is not registered")
      return
    }
    host.dispatch(walletId, request, { promise.resolve(it) }, { promise.reject("NwcRequestFailed", "Native NWC request failed") })
  }

  companion object {
    const val NAME = "NwcMobile"
    @Volatile private var nativeHost: NwcMobileHost? = null
    @Synchronized fun registerHost(host: NwcMobileHost): Boolean {
      if (nativeHost != null) return nativeHost === host
      nativeHost = host
      return true
    }
  }
}
