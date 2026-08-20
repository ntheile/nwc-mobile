import Foundation

/// Runs one NSE wake attempt and resolves its completion path exactly once.
///
/// Construct one coordinator per notification request. The containing NSE must
/// call `timeWillExpire()` from `serviceExtensionTimeWillExpire()`.
public final class NwcNotificationServiceCoordinator: @unchecked Sendable {
  public typealias Completion = @Sendable (NwcWakePresentationHint) -> Void

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

  private let executor: any NwcWakeExecutor
  private let cancellationFactory: NwcWakeCancellationFactory
  private let executionMilliseconds: UInt64
  private let lock = NSLock()
  private var state = State.idle

  public init(
    executor: any NwcWakeExecutor,
    cancellationFactory: @escaping NwcWakeCancellationFactory,
    executionMilliseconds: UInt64
  ) {
    precondition(executionMilliseconds > 0)
    self.executor = executor
    self.cancellationFactory = cancellationFactory
    self.executionMilliseconds = executionMilliseconds
  }

  /// Starts the single request owned by this coordinator.
  ///
  /// Returns `false` without replacing the existing completion path if the
  /// coordinator has already started.
  @discardableResult
  public func start(
    payload: NwcWakePayload,
    completion: @escaping Completion
  ) -> Bool {
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

    let task = Task { [executor, executionMilliseconds, weak self] in
      let hint = await executor.execute(
        payload: payload,
        executionMilliseconds: executionMilliseconds,
        cancellation: cancellation
      )
      self?.finish(with: hint)
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

  /// Cancels in-flight work and chooses the containing application fallback.
  public func timeWillExpire() {
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
    attempt?.completion(.openApplication)
  }

  private func finish(with hint: NwcWakePresentationHint) {
    let completion: Completion?
    lock.lock()
    if case .active(let attempt) = state {
      state = .finished
      completion = attempt.completion
    } else {
      completion = nil
    }
    lock.unlock()
    completion?(hint)
  }
}
