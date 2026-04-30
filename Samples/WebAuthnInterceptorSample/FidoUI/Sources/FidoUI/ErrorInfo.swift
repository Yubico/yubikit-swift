import SwiftUI
import YubiKit

extension FidoUI {
    /// Display model for ``ErrorPanel`` — title/message/icon plus a severity
    /// that picks the icon tint, and a retryability flag that governs whether
    /// the panel shows a Retry button or just Dismiss.
    ///
    /// Constructed at the call site for bespoke errors (see
    /// ``Presenter/showInlineFatal(title:message:icon:serviceName:)``), via
    /// ``from(clientError:)`` for the generic mapping, or via
    /// ``noCredentials(serviceName:)`` when the call site has the service
    /// name to template into the message.
    struct ErrorInfo: Equatable {
        let title: String
        let message: String
        let icon: String
        let severity: Severity
        var isRetryable: Bool = true

        enum Severity: Equatable {
            case critical
            case warning
            case info
        }

        var iconColor: Color {
            switch severity {
            case .critical: .red
            case .warning: .orange
            case .info: .secondary
            }
        }
    }
}

extension FidoUI.ErrorInfo {
    /// Single source of truth for "user cancelled" copy; reached via
    /// `FidoUI.Error.cancelled` and `WebAuthn.ClientError.cancelled`.
    static var cancelled: Self {
        Self(
            title: String(localized: "Cancelled"),
            message: String(localized: "The operation was cancelled."),
            icon: "xmark.circle.fill",
            severity: .info,
            isRetryable: false
        )
    }

    /// `.uvBlocked` reaching the recovery dispatch with no PIN to fall back
    /// to (UV-only authenticator, or `uv: .required`). Distinct from
    /// `.from(.uvBlocked)`'s generic "Verification Failed" copy because at
    /// the recovery layer we know the sensor is permanently locked, not
    /// just rejecting a fingerprint, and the user has to reseat or reset.
    static var uvBlockedNoPIN: Self {
        Self(
            title: String(localized: "Fingerprint Sensor Locked"),
            message: String(
                localized: """
                    Fingerprint verification is blocked on this YubiKey. \
                    Remove and reinsert the key, or reset it, to try again.
                    """
            ),
            icon: "touchid",
            severity: .critical,
            isRetryable: false
        )
    }

    /// `noCredentials` mapping that templates the service name into the body
    /// copy. Kept separate from ``from(clientError:)`` so that overload
    /// doesn't carry a `serviceName` parameter only one branch consumes.
    static func noCredentials(serviceName: String?) -> Self {
        let message: String =
            if let serviceName {
                String(
                    localized:
                        "No passkeys for \(serviceName) exist on this YubiKey."
                )
            } else {
                String(
                    localized:
                        "There are no passkeys registered on this YubiKey for this website."
                )
            }
        return Self(
            title: String(localized: "No Passkeys Found"),
            message: message,
            icon: "person.crop.circle.badge.questionmark.fill",
            severity: .warning,
            isRetryable: false
        )
    }

    static func from(clientError error: WebAuthn.ClientError) -> Self {
        switch error {
        case .noCredentials:
            return .noCredentials(serviceName: nil)
        case .timeout:
            return Self(
                title: String(localized: "Operation Timed Out"),
                message: String(localized: "The operation took too long. Please try again."),
                icon: "clock.badge.xmark.fill",
                severity: .info
            )
        case .cancelled:
            return .cancelled
        case .pinNotSet:
            return Self(
                title: String(localized: "PIN Not Set"),
                message:
                    String(localized: "This YubiKey doesn't have a PIN configured. Please set up a PIN first."),
                icon: "lock.open.fill",
                severity: .warning
            )
        case .pinBlocked:
            return Self(
                title: String(localized: "YubiKey Locked"),
                message:
                    String(
                        localized:
                            "Too many incorrect PIN attempts. Your YubiKey is locked and must be reset."
                    ),
                icon: "lock.slash.fill",
                severity: .critical,
                isRetryable: false
            )
        case .pinAuthBlocked:
            return Self(
                title: String(localized: "Temporarily Locked"),
                message:
                    String(
                        localized:
                            "Too many incorrect attempts. Remove and reinsert your YubiKey to try again."
                    ),
                icon: "lock.slash.fill",
                severity: .critical,
                isRetryable: false
            )
        case .uvRejected, .uvBlocked:
            return Self(
                title: String(localized: "Verification Failed"),
                message:
                    String(localized: "Fingerprint verification failed. Please try again or use your PIN."),
                icon: "touchid",
                severity: .warning
            )
        case .pinComplexity:
            return Self(
                title: String(localized: "PIN Not Accepted"),
                message:
                    String(
                        localized:
                            "The PIN doesn't meet your YubiKey's complexity requirements. Try a stronger PIN."
                    ),
                icon: "lock.trianglebadge.exclamationmark.fill",
                severity: .warning
            )
        case .forcePinChange:
            return Self(
                title: String(localized: "PIN Change Required"),
                message:
                    String(
                        localized:
                            "Your YubiKey requires a PIN change before it can be used."
                    ),
                icon: "key.rotate",
                severity: .warning
            )
        case .credentialExcluded:
            return Self(
                title: String(localized: "Already Registered"),
                message:
                    String(localized: "This YubiKey is already registered with this website."),
                icon: "person.fill.checkmark",
                severity: .warning,
                isRetryable: false
            )
        case .storageFull:
            return Self(
                title: String(localized: "Storage Full"),
                message:
                    String(localized: "Your YubiKey's storage is full. Remove some passkeys to add new ones."),
                icon: "externaldrive.badge.xmark",
                severity: .critical,
                isRetryable: false
            )
        case .authenticatorNotAvailable:
            return Self(
                title: String(localized: "Key Disconnected"),
                message:
                    String(localized: "The YubiKey was disconnected. Please reconnect and try again."),
                icon: "cable.connector",
                severity: .warning
            )
        case .unsupportedAlgorithm:
            return Self(
                title: String(localized: "Not Supported"),
                message:
                    String(localized: "This YubiKey doesn't support the required cryptographic algorithm."),
                icon: "xmark.shield.fill",
                severity: .warning
            )
        case .notSupported(let message, _):
            return Self(
                title: String(localized: "Not Supported"),
                message: message,
                icon: "xmark.shield.fill",
                severity: .warning
            )
        case .invalidRequest(let message, _):
            return Self(
                title: String(localized: "Invalid Request"),
                message: message,
                icon: "exclamationmark.triangle.fill",
                severity: .critical
            )
        case .pinRejected:
            return Self(
                title: String(localized: "Incorrect PIN"),
                message: String(localized: "The PIN you entered is incorrect."),
                icon: "xmark.circle.fill",
                severity: .warning
            )
        case .pinRequired:
            return Self(
                title: String(localized: "PIN Required"),
                message:
                    String(localized: "This operation requires your YubiKey PIN."),
                icon: "key.fill",
                severity: .warning
            )
        case .pinTokenExpired:
            return Self(
                title: String(localized: "Session Expired"),
                message:
                    String(localized: "Your session has expired. Please try again."),
                icon: "clock.badge.xmark.fill",
                severity: .info
            )
        case .ctapError(let ctapError, _):
            return Self(
                title: String(localized: "YubiKey Error"),
                message:
                    String(
                        localized: "The YubiKey returned an error: \(String(describing: ctapError))"
                    ),
                icon: "exclamationmark.triangle.fill",
                severity: .critical
            )
        case .internalError(let message, let source):
            // Don't surface SDK internals (file paths, transport stack
            // traces) to the user — log them and show a generic message.
            fidoLog("ErrorInfo", "internalError at \(source.file):\(source.line): \(message)")
            return Self(
                title: String(localized: "Internal Error"),
                message: String(
                    localized: "An unexpected error occurred. Please try again."
                ),
                icon: "exclamationmark.triangle.fill",
                severity: .critical
            )
        }
    }
}
