import SwiftUI
import YubiKit

extension FidoUI {
    /// User-facing classification of a ceremony failure. All fields are
    /// sanitized — no SDK source locations, no author-controlled detail
    /// strings, no raw CTAP codes.
    struct ErrorInfo: Equatable, Sendable {
        let title: String
        let message: String
        let icon: String
        let severity: Severity
        let isRetryable: Bool

        enum Severity: Equatable, Sendable {
            case critical
            case warning
            case info
        }

        init(
            title: String,
            message: String,
            icon: String,
            severity: Severity,
            isRetryable: Bool = true
        ) {
            self.title = title
            self.message = message
            self.icon = icon
            self.severity = severity
            self.isRetryable = isRetryable
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
    static var cancelled: Self {
        Self(
            title: String(localized: "Cancelled"),
            message: String(localized: "The operation was cancelled."),
            icon: "xmark.circle.fill",
            severity: .info,
            isRetryable: false
        )
    }

    static var nfcConnectionFailed: Self {
        Self(
            title: String(localized: "Unable to Read YubiKey"),
            message: String(localized: "Hold your YubiKey near the top of your iPhone and try again."),
            icon: "wave.3.right",
            severity: .warning,
            isRetryable: false
        )
    }

    /// Used when `.uvBlocked` lands with no PIN fallback — the sensor is
    /// permanently locked and the user has to reseat or reset.
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

    static func noCredentials(serviceName: String?) -> Self {
        let message: String =
            if let serviceName, !serviceName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
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
        case .uvRejected:
            return Self(
                title: String(localized: "Verification Failed"),
                message:
                    String(localized: "Fingerprint verification failed. Please try again or use your PIN."),
                icon: "touchid",
                severity: .warning
            )
        case .uvBlocked:
            return .uvBlockedNoPIN
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
                icon: "arrow.triangle.2.circlepath",
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
                    String(localized: "The YubiKey was disconnected. Reconnect it and start again."),
                icon: "cable.connector",
                severity: .warning,
                isRetryable: false
            )
        case .unsupportedAlgorithm:
            return Self(
                title: String(localized: "Not Supported"),
                message:
                    String(localized: "This YubiKey doesn't support the required cryptographic algorithm."),
                icon: "xmark.shield.fill",
                severity: .warning,
                isRetryable: false
            )
        case .notSupported(let detail, let source):
            // SDK's `detail` is author-controlled diagnostic copy — log,
            // don't surface.
            fidoLog("ErrorInfo", "notSupported at \(source.file):\(source.line): \(detail)")
            return Self(
                title: String(localized: "Not Supported"),
                message: String(
                    localized: "This YubiKey doesn't support the requested operation."
                ),
                icon: "xmark.shield.fill",
                severity: .warning,
                isRetryable: false
            )
        case .invalidRequest(let detail, let source):
            fidoLog("ErrorInfo", "invalidRequest at \(source.file):\(source.line): \(detail)")
            return Self(
                title: String(localized: "Invalid Request"),
                message: String(
                    localized: "The website made a request this YubiKey can't satisfy."
                ),
                icon: "exclamationmark.triangle.fill",
                severity: .critical,
                isRetryable: false
            )
        case .pinRejected:
            return Self(
                title: String(localized: "Incorrect PIN"),
                message: String(localized: "The PIN you entered is incorrect."),
                icon: "xmark.circle.fill",
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
        case .ctapError(let ctapError, let source):
            // Raw CTAP identifiers are meaningless to a user — log only.
            fidoLog("ErrorInfo", "ctapError at \(source.file):\(source.line): \(String(describing: ctapError))")
            return Self(
                title: String(localized: "YubiKey Error"),
                message: String(localized: "The YubiKey reported an error. Please try again."),
                icon: "exclamationmark.triangle.fill",
                severity: .critical
            )
        case .internalError(let message, let source):
            // SDK internals (paths, transport traces) — log only.
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
