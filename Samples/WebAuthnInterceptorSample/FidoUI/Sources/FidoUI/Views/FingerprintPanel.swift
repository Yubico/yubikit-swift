import SwiftUI

/// `onUsePIN` (when non-nil) routes the live ceremony into the PIN
/// closure without restarting the connection.
struct FingerprintPanel: View {
    let onCancel: () -> Void
    let onUsePIN: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "touchid",
                title: String(localized: "Touch Fingerprint Sensor"),
                subtitle: String(localized: "Touch the fingerprint sensor on your YubiKey"),
                subtitleBottomPadding: 16,
                titleIdentifier: "fingerprint_title",
                subtitleIdentifier: "fingerprint_subtitle"
            )

            if let onUsePIN {
                SecondaryButton(
                    label: String(localized: "Use PIN Instead"),
                    identifier: "use_pin_button"
                ) { onUsePIN() }
                .padding(.bottom, 16)
            }

            CancelButton(identifier: "fingerprint_cancel_button") { onCancel() }
        }
        .panelPadding()
    }
}

/// No "Try Again" — the sensor won't unlock until the key is reseated.
struct FingerprintLockedPanel: View {
    let onUsePIN: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "touchid",
                tint: .red,
                title: String(localized: "Fingerprint Sensor Locked"),
                subtitle: String(
                    localized:
                        "Fingerprint verification is blocked on this YubiKey. Use your PIN to continue."
                ),
                titleIdentifier: "fingerprint_locked_title",
                subtitleIdentifier: "fingerprint_locked_subtitle"
            )

            PrimaryButton(
                label: String(localized: "Use PIN Instead"),
                identifier: "use_pin_button"
            ) { onUsePIN() }
            .padding(.bottom, 16)

            CancelButton(identifier: "fingerprint_locked_cancel_button") { onCancel() }
        }
        .panelPadding()
    }
}

struct FingerprintRetryPanel: View {
    let errorMessage: String
    let retries: Int
    let onRetryUV: () -> Void
    let onUsePIN: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "touchid",
                title: String(localized: "Touch Fingerprint Sensor"),
                subtitle: String(localized: "Touch the fingerprint sensor on your YubiKey"),
                subtitleBottomPadding: 12,
                titleIdentifier: "fingerprint_retry_title",
                subtitleIdentifier: "fingerprint_retry_subtitle"
            )

            ValidationText(
                message: errorMessage,
                isError: true,
                identifier: "fingerprint_retry_error_message"
            )

            ValidationText(
                message: retriesText(retries),
                isError: false,
                identifier: "fingerprint_retry_retries_remaining"
            )

            PrimaryButton(
                label: String(localized: "Try Again"),
                identifier: "retry_uv_button"
            ) { onRetryUV() }
            .padding(.top, 12)
            .padding(.bottom, 8)

            SecondaryButton(
                label: String(localized: "Use PIN Instead"),
                identifier: "use_pin_button"
            ) { onUsePIN() }
            .padding(.bottom, 16)

            CancelButton(identifier: "fingerprint_retry_cancel_button") { onCancel() }
        }
        .panelPadding()
    }
}

#Preview("Fingerprint") {
    FidoUI.PanelView(model: .preview(.fingerprint(onCancel: {}, onUsePIN: {})))
        .fidoAlertChrome()
}

#Preview("Fingerprint - No PIN Fallback") {
    FidoUI.PanelView(model: .preview(.fingerprint(onCancel: {}, onUsePIN: nil)))
        .fidoAlertChrome()
}

#Preview("Fingerprint - Retry") {
    FidoUI.PanelView(
        model: .preview(
            .fingerprintRetry(
                errorMessage: "Fingerprint not recognized",
                retries: 3,
                onRetryUV: {},
                onUsePIN: {},
                onCancel: {}
            )
        )
    )
    .fidoAlertChrome()
}

#Preview("Fingerprint - Locked") {
    FidoUI.PanelView(
        model: .preview(.fingerprintLocked(onUsePIN: {}, onCancel: {}))
    )
    .fidoAlertChrome()
}
