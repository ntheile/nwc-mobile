package org.nwc.mobile.example

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.nwc.mobile.*

/** Offline read-only fixture. Never attach this public identity to a real relay. */
class ExampleHost(context: Context) : MobileWalletFactory, MobileWalletBackend,
    MobileRelayTransport, MobileSecretProvider, MobileClientSecretStore {
    private val database = File(context.noBackupFilesDir, "nwc.sqlite").absolutePath
    private val preferences = context.getSharedPreferences("nwc-demo-secrets", Context.MODE_PRIVATE)
    private val alias = "org.nwc.mobile.example.clients"
    private val publicKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    override fun openWallet(walletId: String): MobileWallet {
        if (walletId != "primary") throw MobileEngineException.NotFound()
        return MobileWallet(MobileNwcEngine.open(database, this, this, this),
            MobileWalletConfig(publicKey, listOf("wss://relay.example"), null), this)
    }

    override suspend fun getInfo(timeoutMilliseconds: ULong, cancellation: MobileCancellation) =
        MobileWalletInfo(publicKey, listOf(MobileNwcMethod.GET_INFO, MobileNwcMethod.GET_BALANCE), emptyList())
    override suspend fun getBalance(timeoutMilliseconds: ULong, cancellation: MobileCancellation) = 0uL
    override suspend fun makeInvoice(request: MobileMakeInvoiceRequest, timeoutMilliseconds: ULong, cancellation: MobileCancellation): MobileCreatedInvoice = throw MobileHostException.Rejected()
    override suspend fun quotePayment(invoice: String, amountMsat: ULong?, timeoutMilliseconds: ULong, cancellation: MobileCancellation): MobilePaymentQuote = throw MobileHostException.Rejected()
    override suspend fun paymentStatus(paymentHashHex: String, timeoutMilliseconds: ULong, cancellation: MobileCancellation): MobilePaymentStatus = throw MobileHostException.NotFound()
    override suspend fun startPayment(request: MobilePayInvoiceRequest, timeoutMilliseconds: ULong, cancellation: MobileCancellation): MobilePaymentStatus = throw MobileHostException.Rejected()
    override suspend fun lookupInvoice(request: MobileInvoiceLookup, timeoutMilliseconds: ULong, cancellation: MobileCancellation): MobileWalletTransaction? = null
    override suspend fun listTransactions(request: MobileListTransactionsRequest, timeoutMilliseconds: ULong, cancellation: MobileCancellation): List<MobileWalletTransaction> = emptyList()
    override suspend fun fetchEvent(relayUrl: String, eventIdHex: String, maximumEventBytes: ULong, timeoutMilliseconds: ULong, cancellation: MobileCancellation): String? = null
    override suspend fun publishEvent(relayUrl: String, eventJson: String, timeoutMilliseconds: ULong, cancellation: MobileCancellation): Unit = throw MobileHostException.Unavailable()
    override fun loadNwcSecret(connectionId: String) = ByteArray(32).also { it[31] = 1 }

    private fun encryptionKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
            generateKey()
        }
    }

    // Example is single-process and backup is disabled in AndroidManifest.xml.
    // Production multi-process workers need a shared transactional secret store.
    @Synchronized override fun load(key: String): String? {
        val encoded = preferences.getString(key, null) ?: return null
        return secure {
            val bytes = Base64.decode(encoded, Base64.NO_WRAP)
            require(bytes.size >= 28)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            cipher.doFinal(bytes.copyOfRange(12, bytes.size)).toString(Charsets.UTF_8)
        }
    }
    @Synchronized override fun store(key: String, secret: String) = secure {
        check(!preferences.contains(key))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
        val encoded = Base64.encodeToString(cipher.iv + cipher.doFinal(secret.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        check(preferences.edit().putString(key, encoded).commit())
    }
    @Synchronized override fun delete(key: String) = secure {
        check(preferences.edit().remove(key).commit())
    }
    private fun <T> secure(action: () -> T): T = try { action() } catch (_: Exception) {
        throw MobileEngineException.DatabaseUnavailable()
    }
}
