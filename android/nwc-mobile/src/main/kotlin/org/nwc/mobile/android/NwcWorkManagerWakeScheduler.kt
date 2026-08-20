package org.nwc.mobile.android

import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.ListenableWorker
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.WorkManager
import androidx.work.WorkRequest
import java.util.concurrent.TimeUnit

/**
 * Bounded FCM-to-WorkManager handoff.
 *
 * A wallet's `FirebaseMessagingService` passes `RemoteMessage.data` here and
 * returns immediately. Invalid envelopes are rejected without logging values.
 */
class NwcWorkManagerWakeScheduler(
  private val workManager: WorkManager,
  private val workerClass: Class<out ListenableWorker>,
  private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1_000 },
) {
  /** Returns false when the untrusted data message is malformed or oversized. */
  fun schedule(remoteData: Map<String, String>): Boolean {
    val decoded = decodeNwcWakePayload(remoteData, nowSeconds())
    if (decoded !is NwcWakePayloadDecodeResult.Accepted) {
      return false
    }

    val payload = decoded.payload
    val request = OneTimeWorkRequest.Builder(workerClass)
      .setInputData(payload.toWorkData())
      .setConstraints(
        Constraints.Builder()
          .setRequiredNetworkType(NetworkType.CONNECTED)
          .build()
      )
      .setBackoffCriteria(
        BackoffPolicy.EXPONENTIAL,
        WorkRequest.MIN_BACKOFF_MILLIS,
        TimeUnit.MILLISECONDS,
      )
      .addTag(NWC_WAKE_WORK_TAG)
      .build()

    workManager.enqueueUniqueWork(
      payload.uniqueWorkName(),
      ExistingWorkPolicy.KEEP,
      request,
    )
    return true
  }
}
