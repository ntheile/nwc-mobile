import Foundation

/// Aggregate, non-sensitive result of one payment reconciliation pass.
public struct NwcPaymentMaintenanceReport: Sendable, Equatable {
  public let examined: UInt16
  public let succeeded: UInt16
  public let failed: UInt16
  public let unresolved: UInt16
  public let deferred: UInt16
  public let interrupted: Bool
  public let needsRetry: Bool

  public init(
    examined: UInt16,
    succeeded: UInt16,
    failed: UInt16,
    unresolved: UInt16,
    deferred: UInt16,
    interrupted: Bool,
    needsRetry: Bool
  ) {
    self.examined = examined
    self.succeeded = succeeded
    self.failed = failed
    self.unresolved = unresolved
    self.deferred = deferred
    self.interrupted = interrupted
    self.needsRetry = needsRetry
  }
}

/// Aggregate, non-sensitive result of one wake-registration outbox pass.
public struct NwcRegistrationMaintenanceReport: Sendable, Equatable {
  public let examined: UInt16
  public let applied: UInt16
  public let deferred: UInt16
  public let superseded: UInt16
  public let interrupted: Bool
  public let needsRetry: Bool

  public init(
    examined: UInt16,
    applied: UInt16,
    deferred: UInt16,
    superseded: UInt16,
    interrupted: Bool,
    needsRetry: Bool
  ) {
    self.examined = examined
    self.applied = applied
    self.deferred = deferred
    self.superseded = superseded
    self.interrupted = interrupted
    self.needsRetry = needsRetry
  }
}

/// Stable lifecycle result for one foreground or background maintenance run.
public enum NwcMaintenanceDisposition: Sendable, Equatable {
  case completed(
    payments: NwcPaymentMaintenanceReport,
    registrations: NwcRegistrationMaintenanceReport
  )
  case retry
  case cancelled

  /// Whether the application should schedule another maintenance pass.
  public var needsRetry: Bool {
    switch self {
    case .completed(let payments, let registrations):
      payments.needsRetry || registrations.needsRetry
    case .retry:
      true
    case .cancelled:
      true
    }
  }
}

/// Thin adapter implemented by the wallet using generated `NwcMobile` types.
///
/// Implementations map generated aggregate reports into these package report
/// types. Raw wallet and provider errors must remain in protected app logs.
public protocol NwcMaintenanceExecutor: Sendable {
  /// Reconciles already-reserved payments without initiating new payments.
  func reconcilePayments(
    maximumAttempts: UInt16,
    executionMilliseconds: UInt64,
    cancellation: any NwcWakeCancellation
  ) async throws -> NwcPaymentMaintenanceReport

  /// Applies due, revision-bound wake-provider registration changes.
  func processWakeRegistrations(
    maximumChanges: UInt16,
    executionMilliseconds: UInt64,
    cancellation: any NwcWakeCancellation
  ) async throws -> NwcRegistrationMaintenanceReport
}

/// Runs payment and registration recovery without overlapping passes.
///
/// Start this coordinator when the app enters the foreground or from a bounded
/// background task. Call `cancel()` before the OS suspends or expires that task.
public final class NwcMaintenanceCoordinator: @unchecked Sendable {
  public typealias Completion = @Sendable (NwcMaintenanceDisposition) -> Void

  private struct ActiveAttempt {
    let cancellation: any NwcWakeCancellation
    let completion: Completion
    var task: Task<Void, Never>?
  }

  private enum State {
    case idle
    case active(ActiveAttempt)
    case finished
  }

  private let executor: any NwcMaintenanceExecutor
  private let cancellationFactory: NwcWakeCancellationFactory
  private let maximumPaymentAttempts: UInt16
  private let maximumRegistrationChanges: UInt16
  private let paymentExecutionMilliseconds: UInt64
  private let registrationExecutionMilliseconds: UInt64
  private let lock = NSLock()
  private var state = State.idle

  public init(
    executor: any NwcMaintenanceExecutor,
    cancellationFactory: @escaping NwcWakeCancellationFactory,
    maximumPaymentAttempts: UInt16 = 100,
    maximumRegistrationChanges: UInt16 = 100,
    paymentExecutionMilliseconds: UInt64,
    registrationExecutionMilliseconds: UInt64
  ) {
    precondition((1...100).contains(maximumPaymentAttempts))
    precondition((1...100).contains(maximumRegistrationChanges))
    precondition(paymentExecutionMilliseconds > 0)
    precondition(registrationExecutionMilliseconds > 0)
    self.executor = executor
    self.cancellationFactory = cancellationFactory
    self.maximumPaymentAttempts = maximumPaymentAttempts
    self.maximumRegistrationChanges = maximumRegistrationChanges
    self.paymentExecutionMilliseconds = paymentExecutionMilliseconds
    self.registrationExecutionMilliseconds = registrationExecutionMilliseconds
  }

  /// Starts the single maintenance pass owned by this coordinator.
  ///
  /// Returns `false` without replacing the existing completion path after the
  /// coordinator has started or was cancelled before starting.
  @discardableResult
  public func start(completion: @escaping Completion) -> Bool {
    let cancellation = cancellationFactory()
    lock.lock()
    guard case .idle = state else {
      lock.unlock()
      return false
    }
    state = .active(
      ActiveAttempt(
        cancellation: cancellation,
        completion: completion,
        task: nil
      )
    )
    lock.unlock()

    let task = Task {
      [
        executor,
        maximumPaymentAttempts,
        maximumRegistrationChanges,
        paymentExecutionMilliseconds,
        registrationExecutionMilliseconds,
        weak self,
      ] in
      let disposition: NwcMaintenanceDisposition
      do {
        let payments = try await executor.reconcilePayments(
          maximumAttempts: maximumPaymentAttempts,
          executionMilliseconds: paymentExecutionMilliseconds,
          cancellation: cancellation
        )
        try Task.checkCancellation()
        let registrations = try await executor.processWakeRegistrations(
          maximumChanges: maximumRegistrationChanges,
          executionMilliseconds: registrationExecutionMilliseconds,
          cancellation: cancellation
        )
        try Task.checkCancellation()
        disposition = .completed(payments: payments, registrations: registrations)
      } catch is CancellationError {
        disposition = .cancelled
      } catch {
        disposition = .retry
      }
      self?.finish(with: disposition)
    }

    lock.lock()
    if case .active(let attempt) = state {
      state = .active(
        ActiveAttempt(
          cancellation: attempt.cancellation,
          completion: attempt.completion,
          task: task
        )
      )
      lock.unlock()
    } else {
      lock.unlock()
      task.cancel()
    }
    return true
  }

  /// Cancels native and Rust work and resolves the completion exactly once.
  public func cancel() {
    let attempt: ActiveAttempt?
    lock.lock()
    if case .active(let activeAttempt) = state {
      state = .finished
      attempt = activeAttempt
    } else if case .idle = state {
      state = .finished
      attempt = nil
    } else {
      attempt = nil
    }
    lock.unlock()

    attempt?.cancellation.cancel()
    attempt?.task?.cancel()
    attempt?.completion(.cancelled)
  }

  private func finish(with disposition: NwcMaintenanceDisposition) {
    let completion: Completion?
    lock.lock()
    if case .active(let attempt) = state {
      state = .finished
      completion = attempt.completion
    } else {
      completion = nil
    }
    lock.unlock()
    completion?(disposition)
  }
}
