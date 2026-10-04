package org.nwc.mobile.example

import com.nwcmobile.reactnative.NwcMobileHost
import com.nwcmobile.reactnative.NwcMobileModule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.nwc.mobile.dispatchMobileWalletJson

/** Native bootstrap only; the containing app owns and trusts its consent UI. */
object ReactNativeWalletHost {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val host = NwcMobileHost { walletId, request, resolve, reject ->
        scope.launch {
            try { resolve(dispatchMobileWalletJson(walletId, request)) }
            catch (_: Exception) { reject() }
        }
    }
    fun register() { check(NwcMobileModule.registerHost(host)) }
}
