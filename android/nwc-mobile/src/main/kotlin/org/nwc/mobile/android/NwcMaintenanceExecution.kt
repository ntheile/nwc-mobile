package org.nwc.mobile.android

/** Aggregate, non-sensitive result of one payment reconciliation pass. */
data class NwcPaymentMaintenanceReport(
  val examined: UShort,
  val succeeded: UShort,
  val failed: UShort,
  val unresolved: UShort,
  val deferred: UShort,
  val interrupted: Boolean,
  val needsRetry: Boolean,
)

/** Aggregate, non-sensitive result of one wake-registration outbox pass. */
data class NwcRegistrationMaintenanceReport(
  val examined: UShort,
  val applied: UShort,
  val deferred: UShort,
  val superseded: UShort,
  val interrupted: Boolean,
  val needsRetry: Boolean,
)

/** Wallet-owned bridge to generated `MobileNwcEngine` maintenance methods. */
interface NwcMaintenanceExecutor {
  /** Reconciles already-reserved payments without initiating new payments. */
  suspend fun reconcilePayments(
    maximumAttempts: UShort,
    executionMilliseconds: Long,
    cancellation: NwcWakeCancellation,
  ): NwcPaymentMaintenanceReport

  /** Applies due, revision-bound wake-provider registration changes. */
  suspend fun processWakeRegistrations(
    maximumChanges: UShort,
    executionMilliseconds: Long,
    cancellation: NwcWakeCancellation,
  ): NwcRegistrationMaintenanceReport
}

internal suspend fun executeNwcMaintenance(
  executor: NwcMaintenanceExecutor,
  maximumPaymentAttempts: UShort,
  maximumRegistrationChanges: UShort,
  paymentExecutionMilliseconds: Long,
  registrationExecutionMilliseconds: Long,
  cancellation: NwcWakeCancellation,
): NwcPlatformWorkResult {
  val payments = executor.reconcilePayments(
    maximumAttempts = maximumPaymentAttempts,
    executionMilliseconds = paymentExecutionMilliseconds,
    cancellation = cancellation,
  )
  val registrations = executor.processWakeRegistrations(
    maximumChanges = maximumRegistrationChanges,
    executionMilliseconds = registrationExecutionMilliseconds,
    cancellation = cancellation,
  )
  return if (payments.needsRetry || registrations.needsRetry) {
    NwcPlatformWorkResult.RETRY
  } else {
    NwcPlatformWorkResult.SUCCESS
  }
}
