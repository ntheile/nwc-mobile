# nwc-mobile Android

This Android library is the thin FCM and WorkManager lifecycle adapter for
`nwc-mobile`. Rust remains responsible for Nostr validation, authorization,
durable claims, replay handling, relay access policy, and payment decisions.

The library targets API 23 and newer and compiles against API 36. It uses
WorkManager 2.11.2.

## FCM handoff

The wallet owns `FirebaseMessagingService`; this package deliberately does not
depend on Firebase. Pass only `RemoteMessage.data` to a retained scheduler and
return promptly:

```kotlin
class WalletMessagingService : FirebaseMessagingService() {
  override fun onMessageReceived(message: RemoteMessage) {
    val scheduler = NwcWorkManagerWakeScheduler(
      WorkManager.getInstance(applicationContext),
      WalletNwcWakeWorker::class.java,
    )
    scheduler.schedule(message.data)
  }
}
```

The scheduler accepts the same `nwc_relay`, `nwc_event_id`, and
`nwc_wallet_service_pubkey` keys as the Apple helper. It bounds transport data,
records a trusted device receive timestamp, requires network connectivity, and
uses unique work with `ExistingWorkPolicy.KEEP`. The work name contains a digest
of the canonical event id, never the event id or relay itself.

`nwc_event_json` is deliberately not copied into WorkManager's database. The
worker passes `null` for the generated envelope's embedded event and lets Rust
fetch and validate the exact event. Pushes must never contain a client secret,
complete NWC URI, decrypted request, invoice, amount, counterparty, or wallet
error.

## Worker bridge

Subclass `NwcWakeWorker` and create adapters around generated `NwcMobile` types:

```kotlin
class WalletNwcWakeWorker(
  context: Context,
  parameters: WorkerParameters,
) : NwcWakeWorker(context, parameters) {
  override val executionMilliseconds = 8 * 60 * 1_000L

  override fun createCancellation(): NwcWakeCancellation =
    WalletRustCancellation()

  override fun createExecutor(): NwcWakeExecutor =
    WalletRustWakeExecutor()
}
```

The executor constructs `MobileWakeEnvelope` using the payload and its recorded
receive timestamp, calls `validateWakeEnvelope`, and then calls
`MobileNwcEngine.executeWake`. Map `Completed` and `AlreadyProcessed` to
`COMPLETED`, `RetryAfter` to `RETRY`, `QueuedForApplication` to
`OPEN_APPLICATION`, and a terminal validation or policy rejection to
`REJECTED`. Do not expose remote error bodies through exceptions, logs, worker
output, notifications, or analytics.

`NwcWakeCancellation.cancel()` must be thread-safe, idempotent, and monotonic.
The worker calls it both when its future is cancelled and when WorkManager calls
`onStopped()`. The application and worker open the same app-owned Rust ledger;
the unique WorkManager name is only a scheduling optimization, not replay
protection.

## Durable maintenance

`NwcWorkManagerMaintenanceScheduler` enqueues one unique, network-constrained
maintenance pass without putting wallet or routing data into WorkManager state.
A wallet subclasses `NwcMaintenanceWorker` and supplies a
`NwcMaintenanceExecutor` backed by the generated engine's
`reconcilePayments` and `processWakeRegistrations` methods. The worker runs both
bounded passes in sequence, requests retry when either report has durable work
remaining, and immediately cancels the shared Rust scope when WorkManager stops
the future.

## Build integrity

Versions are exact, dependency locking is enabled, and Gradle verifies committed
SHA-256 hashes for downloaded artifacts. Test locally with:

```sh
gradle --project-dir android/nwc-mobile --no-daemon build lint
```

For an intentional dependency update, regenerate locks and verification metadata
in an isolated environment, then review the complete coordinate and checksum
diff before committing it.
