package org.nwc.mobile.android

import java.util.concurrent.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NwcMaintenanceExecutionTest {
  @Test
  fun runsBothPassesInOrderAndAggregatesRetry() = runBlocking {
    val calls = mutableListOf<String>()
    val executor = TestMaintenanceExecutor(
      calls = calls,
      payments = paymentReport(needsRetry = true),
      registrations = registrationReport(needsRetry = false),
    )

    val result = executeNwcMaintenance(
      executor = executor,
      maximumPaymentAttempts = 10u,
      maximumRegistrationChanges = 20u,
      paymentExecutionMilliseconds = 1_000,
      registrationExecutionMilliseconds = 2_000,
      cancellation = NwcWakeCancellation {},
    )

    assertEquals(listOf("payments:10:1000", "registrations:20:2000"), calls)
    assertEquals(NwcPlatformWorkResult.RETRY, result)
  }

  @Test
  fun successfulReportsCompletePlatformWork() = runBlocking {
    val result = executeNwcMaintenance(
      executor = TestMaintenanceExecutor(
        calls = mutableListOf(),
        payments = paymentReport(needsRetry = false),
        registrations = registrationReport(needsRetry = false),
      ),
      maximumPaymentAttempts = 1u,
      maximumRegistrationChanges = 1u,
      paymentExecutionMilliseconds = 1,
      registrationExecutionMilliseconds = 1,
      cancellation = NwcWakeCancellation {},
    )

    assertEquals(NwcPlatformWorkResult.SUCCESS, result)
  }

  @Test
  fun cancellationStopsBeforeRegistrationAndPropagates() {
    val calls = mutableListOf<String>()
    val executor = TestMaintenanceExecutor(
      calls = calls,
      payments = paymentReport(needsRetry = false),
      registrations = registrationReport(needsRetry = false),
      cancelPayments = true,
    )

    assertThrows(CancellationException::class.java) {
      runBlocking {
        executeNwcMaintenance(
          executor = executor,
          maximumPaymentAttempts = 1u,
          maximumRegistrationChanges = 1u,
          paymentExecutionMilliseconds = 1,
          registrationExecutionMilliseconds = 1,
          cancellation = NwcWakeCancellation {},
        )
      }
    }
    assertEquals(listOf("payments:1:1"), calls)
  }

  private class TestMaintenanceExecutor(
    private val calls: MutableList<String>,
    private val payments: NwcPaymentMaintenanceReport,
    private val registrations: NwcRegistrationMaintenanceReport,
    private val cancelPayments: Boolean = false,
  ) : NwcMaintenanceExecutor {
    override suspend fun reconcilePayments(
      maximumAttempts: UShort,
      executionMilliseconds: Long,
      cancellation: NwcWakeCancellation,
    ): NwcPaymentMaintenanceReport {
      calls += "payments:$maximumAttempts:$executionMilliseconds"
      if (cancelPayments) {
        throw CancellationException()
      }
      return payments
    }

    override suspend fun processWakeRegistrations(
      maximumChanges: UShort,
      executionMilliseconds: Long,
      cancellation: NwcWakeCancellation,
    ): NwcRegistrationMaintenanceReport {
      calls += "registrations:$maximumChanges:$executionMilliseconds"
      return registrations
    }
  }

  private companion object {
    fun paymentReport(needsRetry: Boolean) = NwcPaymentMaintenanceReport(
      examined = 0u,
      succeeded = 0u,
      failed = 0u,
      unresolved = 0u,
      deferred = 0u,
      interrupted = false,
      needsRetry = needsRetry,
    )

    fun registrationReport(needsRetry: Boolean) = NwcRegistrationMaintenanceReport(
      examined = 0u,
      applied = 0u,
      deferred = 0u,
      superseded = 0u,
      interrupted = false,
      needsRetry = needsRetry,
    )
  }
}
