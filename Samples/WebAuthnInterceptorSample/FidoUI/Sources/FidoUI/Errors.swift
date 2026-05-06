import Foundation
import YubiKit

extension FidoUI {
    /// Error thrown from FidoUI public entry points.
    ///
    /// Use ``info`` for user-facing copy — the raw `.webAuthn(...)` payload
    /// is diagnostic only and may carry SDK source locations or
    /// author-controlled detail strings that aren't safe to display.
    public enum Error: Swift.Error, LocalizedError {
        case cancelled

        /// A WebAuthn error the UI did not absorb (non-retryable, a
        /// setup-recovery signal, or retryable-but-user-dismissed).
        case webAuthn(WebAuthn.ClientError)

        /// Sanitized, user-facing classification — safe to display.
        public var info: FidoUI.ErrorInfo {
            switch self {
            case .cancelled: return .cancelled
            case .webAuthn(let error): return .from(clientError: error)
            }
        }

        public var errorDescription: String? { info.message }
    }
}
