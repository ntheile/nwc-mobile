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

const val NWC_MAINTENANCE_WORK_NAME = "nwc-mobile-maintenance"
const val NWC_MAINTENANCE_WORK_TAG = "nwc-mobile-maintenance"

/** Schedules one network-constrained, deduplicated maintenance pass. */
class NwcWorkManagerMaintenanceScheduler(
  private val workManager: WorkManager,
  private val workerClass: Class<out ListenableWorker>,
) {
  /** Enqueues maintenance only when no existing pass with this name is active. */
  fun schedule() {
    val request = OneTimeWorkRequest.Builder(workerClass)
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
      .addTag(NWC_MAINTENANCE_WORK_TAG)
      .build()

    workManager.enqueueUniqueWork(
      NWC_MAINTENANCE_WORK_NAME,
      ExistingWorkPolicy.KEEP,
      request,
    )
  }
}
