import Foundation
import YubiKit

extension FidoUI {
    /// Unified error type thrown from ``Presenter`` APIs.
    ///
    /// Typed throws need a single concrete type; this enum wraps the two paths
    /// FidoUI can terminate on: user cancel, or a WebAuthn client error that
    /// propagated past the in-sheet retry UI.
    public enum Error: Swift.Error, LocalizedError {
        /// The user cancelled the ceremony (panel X, explicit Cancel, or a
        /// background dismiss triggered by the host).
        case cancelled

        /// A WebAuthn error the UI did not absorb — either non-retryable
        /// (`.pinBlocked`, `.storageFull`), a setup-recovery signal the host
        /// must handle (`.authenticatorNotAvailable`, `.pinNotSet`), or a
        /// retryable error after the user chose Dismiss instead of Retry.
        case webAuthn(WebAuthn.ClientError)

        public var errorDescription: String? {
            switch self {
            case .cancelled:
                return FidoUI.ErrorInfo.cancelled.message
            case .webAuthn(let error):
                // `WebAuthn.ClientError` doesn't conform to `LocalizedError`,
                // so its default `localizedDescription` is the reflection
                // string. Reuse `ErrorInfo` for parity with the user-facing
                // copy.
                return FidoUI.ErrorInfo.from(clientError: error).message
            }
        }
    }
}
