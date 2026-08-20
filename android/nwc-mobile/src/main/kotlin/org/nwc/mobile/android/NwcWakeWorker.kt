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
 * Asynchronous WorkManager adapter around the generated Rust engine.
 *
 * This extends `ListenableWorker` instead of `CoroutineWorker` so WorkManager's
 * stop callback can immediately trip the request-scoped Rust cancellation.
 */
abstract class NwcWakeWorker(
  applicationContext: Context,
  workerParameters: WorkerParameters,
) : ListenableWorker(applicationContext, workerParameters) {
  private val supervisor = SupervisorJob()
  private val scope = CoroutineScope(supervisor + Dispatchers.Default)
  private val requestCancellation: NwcWakeCancellation by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
    createCancellation()
  }

  /** Creates the wallet-owned bridge to generated `NwcMobile` types. */
  protected abstract fun createExecutor(): NwcWakeExecutor

  /** Creates a fresh generated `MobileCancellation` adapter for this attempt. */
  protected abstract fun createCancellation(): NwcWakeCancellation

  /** Rust execution budget; must leave time for WorkManager cancellation. */
  protected abstract val executionMilliseconds: Long

  final override fun startWork(): ListenableFuture<Result> =
    CallbackToFutureAdapter.getFuture { completer ->
      val job = scope.launch {
        try {
          completer.set(runWake())
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
      NWC_WAKE_WORK_TAG
    }

  final override fun onStopped() {
    requestCancellation.cancel()
    scope.cancel()
    super.onStopped()
  }

  private suspend fun runWake(): Result {
    if (executionMilliseconds <= 0) {
      return Result.failure()
    }
    val decoded = decodeNwcWakeWorkData(inputData)
    if (decoded !is NwcWakePayloadDecodeResult.Accepted) {
      return Result.failure()
    }

    val disposition = createExecutor().execute(
      payload = decoded.payload,
      executionMilliseconds = executionMilliseconds,
      cancellation = requestCancellation,
    )
    return when (disposition.platformResult()) {
      NwcPlatformWorkResult.SUCCESS -> Result.success()
      NwcPlatformWorkResult.RETRY -> Result.retry()
    }
  }

  private companion object {
    val DIRECT_EXECUTOR = Executor(Runnable::run)
  }
}
