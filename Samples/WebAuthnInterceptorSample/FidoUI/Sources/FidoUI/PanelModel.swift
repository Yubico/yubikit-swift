import SwiftUI
import YubiKit

extension FidoUI {
    @Observable
    @MainActor
    final class PanelModel {

        enum Operation: Equatable {
            case registration
            case authentication
        }

        /// Case-identity mirror of `Panel`, usable as an `Equatable` animation
        /// trigger (the parent `Panel` can't be `Equatable` — it carries closures).
        enum PanelKind: Equatable {
            case waitingForKey, processing, touch
            case pin, createPIN, changePIN, pinCreated, pinChanged
            case fingerprint, fingerprintRetry, fingerprintLocked
            case credentialPicker, error, success
        }

        enum Panel {
            /// "Insert Your YubiKey" prompt. Shown both for the initial wait
            /// and for mid-ceremony reconnect. `onCancel` is nil on platforms
            /// where the bridge has no usable cancel surface (iOS USB-C /
            /// Lightning reconnect: the user dismisses the sheet directly).
            case waitingForKey(onCancel: (() -> Void)?)
            case processing
            case touch(onCancel: () -> Void)
            case pin(
                PINConfig,
                onSubmit: (String) -> Void,
                onCancel: () -> Void
            )
            case createPIN(
                CreatePINConfig,
                onSubmit: (String) -> Void,
                onCancel: () -> Void
            )
            case changePIN(
                ChangePINConfig,
                onSubmit: (String, String) -> Void,
                onCancel: () -> Void
            )
            case pinCreated(onContinue: () -> Void)
            case pinChanged(onContinue: () -> Void)
            /// Built-in UV in flight. Cancel aborts the ceremony via the SDK
            /// keepalive cancel; `onUsePIN` (when non-nil) routes the
            /// ceremony into the PIN closure on the same connection.
            case fingerprint(
                onCancel: () -> Void,
                onUsePIN: (() -> Void)?
            )
            /// Recovery prompt after a UV miss — user picks Try Again, Use PIN,
            /// or Cancel. Drives the next ceremony attempt's `Authorization.uv`.
            case fingerprintRetry(
                errorMessage: String,
                retries: Int,
                onRetryUV: () -> Void,
                onUsePIN: () -> Void,
                onCancel: () -> Void
            )
            /// Built-in UV is permanently blocked on the authenticator (retries
            /// exhausted). PIN auth still works against a UV-blocked
            /// authenticator, so when `clientPin` is configured the recovery is
            /// "Use PIN"; without PIN the SDK is dead-ended and the user has to
            /// remove/reinsert. This case covers the with-PIN branch — the
            /// no-PIN branch shows `.error` with `ErrorInfo.uvBlocked`.
            case fingerprintLocked(
                onUsePIN: () -> Void,
                onCancel: () -> Void
            )
            case credentialPicker(
                [Credential],
                onSelect: (Int) -> Void,
                onCancel: () -> Void
            )
            case error(
                ErrorInfo,
                onRetry: (() -> Void)?,
                onDismiss: () -> Void
            )
            case success(operation: Operation, wasWired: Bool, onDismiss: () -> Void)

            var kind: PanelKind {
                switch self {
                case .waitingForKey: return .waitingForKey
                case .processing: return .processing
                case .touch: return .touch
                case .pin: return .pin
                case .createPIN: return .createPIN
                case .changePIN: return .changePIN
                case .pinCreated: return .pinCreated
                case .pinChanged: return .pinChanged
                case .fingerprint: return .fingerprint
                case .fingerprintRetry: return .fingerprintRetry
                case .fingerprintLocked: return .fingerprintLocked
                case .credentialPicker: return .credentialPicker
                case .error: return .error
                case .success: return .success
                }
            }
        }

        struct PINConfig: Equatable {
            var minLength: Int = 4
            var errorMessage: String?
            var retries: Int?
            /// Pre-fill the field with a previously-entered PIN on transient retry
            /// (timeout, transport drop). Must be `nil` on a rejection retry so
            /// the user can't blindly resubmit the same wrong PIN.
            var initialPIN: String?
        }

        struct CreatePINConfig: Equatable {
            var minLength: Int = 4
            var errorMessage: String?
        }

        struct ChangePINConfig: Equatable {
            var minLength: Int = 4
            var errorMessage: String?
        }

        struct Credential: Identifiable, Equatable {
            let id: Data
            let name: String
            let displayName: String?
        }

        var isPresented = false
        var panel: Panel = .processing
        var operation: Operation = .registration
        var serviceName = ""
        /// Set to a form's `PanelKind` (`.pin`, `.createPIN`, `.changePIN`) the
        /// moment its submit button fires, cleared when the panel is replaced.
        /// Drives the in-button spinner and suppresses the standalone
        /// `processing` panel while a form-submit is in flight — keeping the
        /// PIN form visible if the SDK rejects and re-arms.
        var submittingForm: PanelKind?

        init() {}

        func reset() {
            isPresented = false
            panel = .processing
            operation = .registration
            serviceName = ""
            submittingForm = nil
        }
    }
}
