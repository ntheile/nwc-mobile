package org.nwc.mobile.android

import org.junit.Assert.assertEquals
import org.junit.Test

class NwcWakeExecutionTest {
  @Test
  fun onlyRetryDispositionRequestsPlatformRetry() {
    assertEquals(
      NwcPlatformWorkResult.RETRY,
      NwcWakeWorkerDisposition.RETRY.platformResult(),
    )
    assertEquals(
      NwcPlatformWorkResult.SUCCESS,
      NwcWakeWorkerDisposition.COMPLETED.platformResult(),
    )
    assertEquals(
      NwcPlatformWorkResult.SUCCESS,
      NwcWakeWorkerDisposition.OPEN_APPLICATION.platformResult(),
    )
    assertEquals(
      NwcPlatformWorkResult.SUCCESS,
      NwcWakeWorkerDisposition.REJECTED.platformResult(),
    )
  }
}
