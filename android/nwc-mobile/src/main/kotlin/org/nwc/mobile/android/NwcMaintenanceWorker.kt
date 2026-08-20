package org.nwc.mobile.android

import android.content.Context
import androidx.concurrent.futures.CallbackToFutureAdapter
import androidx.work.ListenableWorker
import androidx.work.WorkerParameters
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.CancellationException
import java.util.concurrent.Executor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * WorkManager adapter for payment and wake-registration recovery.
 *
 * This extends `ListenableWorker` so WorkManager stop signals immediately trip
 * the request-scoped Rust cancellation instead of waiting for coroutine cleanup.
 */
abstract class NwcMaintenanceWorker(
  applicationContext: Context,
  workerParameters: WorkerParameters,
) : ListenableWorker(applicationContext, workerParameters) {
  private val supervisor = SupervisorJob()
  private val scope = CoroutineScope(supervisor + Dispatchers.Default)
  private val requestCancellation: NwcWakeCancellation by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
    createCancellation()
  }

  /** Creates the wallet-owned bridge to generated `NwcMobile` types. */
  protected abstract fun createExecutor(): NwcMaintenanceExecutor

  /** Creates a fresh generated `MobileCancellation` adapter for this pass. */
  protected abstract fun createCancellation(): NwcWakeCancellation

  /** Maximum payment attempts passed to Rust; the hard limit is 100. */
  protected open val maximumPaymentAttempts: UShort = 100u

  /** Maximum registration changes passed to Rust; the hard limit is 100. */
  protected open val maximumRegistrationChanges: UShort = 100u

  /** Independent Rust execution budget for payment reconciliation. */
  protected abstract val paymentExecutionMilliseconds: Long

  /** Independent Rust execution budget for registration processing. */
  protected abstract val registrationExecutionMilliseconds: Long

  final override fun startWork(): ListenableFuture<Result> =
    CallbackToFutureAdapter.getFuture { completer ->
      val job = scope.launch {
        try {
          completer.set(runMaintenance())
        } catch (_: CancellationException) {
          requestCancellation.cancel()
          completer.setCancelled()
        } catch (_: Exception) {
          completer.set(Result.retry())
        }
      }
      completer.addCancellationListener(
        {
          requestCancellation.cancel()
          job.cancel()
        },
        DIRECT_EXECUTOR,
      )
      NWC_MAINTENANCE_WORK_TAG
    }

  final override fun onStopped() {
    requestCancellation.cancel()
    scope.cancel()
    super.onStopped()
  }

  private suspend fun runMaintenance(): Result {
    if (
      maximumPaymentAttempts !in 1u..100u ||
      maximumRegistrationChanges !in 1u..100u ||
      paymentExecutionMilliseconds <= 0 ||
      registrationExecutionMilliseconds <= 0
    ) {
      return Result.failure()
    }

    return when (
      executeNwcMaintenance(
        executor = createExecutor(),
        maximumPaymentAttempts = maximumPaymentAttempts,
        maximumRegistrationChanges = maximumRegistrationChanges,
        paymentExecutionMilliseconds = paymentExecutionMilliseconds,
        registrationExecutionMilliseconds = registrationExecutionMilliseconds,
        cancellation = requestCancellation,
      )
    ) {
      NwcPlatformWorkResult.SUCCESS -> Result.success()
      NwcPlatformWorkResult.RETRY -> Result.retry()
    }
  }

  private companion object {
    val DIRECT_EXECUTOR = Executor(Runnable::run)
  }
}
