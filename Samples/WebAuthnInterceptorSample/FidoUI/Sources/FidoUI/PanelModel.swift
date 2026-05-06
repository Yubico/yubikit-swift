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

        /// Case-identity mirror of `Panel` — `Panel` itself can't be
        /// Equatable because it carries closures.
        enum PanelKind: Equatable {
            case waitingForKey, processing, touch
            case pin, createPIN, changePIN, pinCreated, pinChanged
            case fingerprint, fingerprintRetry, fingerprintLocked
            case credentialPicker, error, success
        }

        enum Panel {
            /// `onCancel` is nil only on the picker debounce panel (iOS),
            /// where the ceremony is cancelled via `FidoUI.cancel()`.
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
            case fingerprint(
                onCancel: () -> Void,
                onUsePIN: (() -> Void)?
            )
            case fingerprintRetry(
                errorMessage: String,
                retries: Int,
                onRetryUV: () -> Void,
                onUsePIN: () -> Void,
                onCancel: () -> Void
            )
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
            /// Pre-fill on transient retry (timeout, transport drop). Must
            /// be nil on a rejection retry — never let the user blindly
            /// resubmit the same wrong PIN.
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
        /// Latched on form submit. Drives the in-button spinner and keeps
        /// the form visible across SDK rejection re-arms.
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
