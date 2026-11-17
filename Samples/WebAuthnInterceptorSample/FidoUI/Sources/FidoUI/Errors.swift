import Foundation
import YubiKit

extension FidoUI {
    /// Error thrown from FidoUI public entry points.
    ///
    /// Use `localizedDescription` for user-facing copy — the raw `.webAuthn(...)` payload
    /// is diagnostic only and may carry SDK source locations or
    /// author-controlled detail strings that aren't safe to display.
    public enum Error: Swift.Error, LocalizedError {
        case cancelled

        /// Another ceremony is already running on this instance.
        case operationInProgress

        /// The initiating view has no visible window in which to present the ceremony.
        case presentationUnavailable

        /// A WebAuthn error the UI did not absorb (non-retryable, a
        /// setup-recovery signal, or retryable-but-user-dismissed).
        case webAuthn(WebAuthn.ClientError)

        public var errorDescription: String? {
            switch self {
            case .cancelled: FidoUI.ErrorInfo.cancelled.message
            case .operationInProgress: String(localized: "A security key request is already in progress.")
            case .presentationUnavailable: String(localized: "Return to the app window and try again.")
            case .webAuthn(let error): FidoUI.ErrorInfo.from(clientError: error).message
            }
        }
    }
}
