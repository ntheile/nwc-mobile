import Foundation

/// Generic presentation guidance returned after Rust-owned wake policy runs.
///
/// The enum deliberately carries no invoice, amount, counterparty, relay, or
/// remote error text.
public enum NwcWakePresentationHint: Sendable, Equatable {
  case processing
  case completed
  case openApplication
}

/// Cancellation object created for one bounded NSE execution.
public protocol NwcWakeCancellation: AnyObject, Sendable {
  func cancel()
}

/// Thin adapter implemented by the wallet using generated `NwcMobile` types.
///
/// Implementations should validate the payload through `validateWakeEnvelope`,
/// invoke `MobileNwcEngine.executeWake`, and map only its notification hint to
/// `NwcWakePresentationHint`.
public protocol NwcWakeExecutor: Sendable {
  func execute(
    payload: NwcWakePayload,
    executionMilliseconds: UInt64,
    cancellation: any NwcWakeCancellation
  ) async -> NwcWakePresentationHint
}

/// Creates a new native/Rust cancellation bridge for every request.
public typealias NwcWakeCancellationFactory =
  @Sendable () -> any NwcWakeCancellation
