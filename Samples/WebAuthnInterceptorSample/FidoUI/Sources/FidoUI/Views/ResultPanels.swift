import SwiftUI

struct ErrorPanel: View {
    let info: FidoUI.ErrorInfo
    let onRetry: (() -> Void)?
    let onDismiss: () -> Void
    @State private var didAppear = false

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: info.icon,
                tint: info.iconColor,
                title: info.title,
                subtitle: info.message,
                titleIdentifier: "error_title",
                subtitleIdentifier: "error_message"
            )

            if let onRetry {
                PrimaryButton(
                    label: String(localized: "Retry"),
                    identifier: "retry_button"
                ) { onRetry() }
                .padding(.bottom, 16)

                CancelButton(identifier: "dismiss_button") { onDismiss() }
            } else {
                PrimaryButton(
                    label: String(localized: "OK"),
                    identifier: "dismiss_button"
                ) { onDismiss() }
            }
        }
        .panelPadding()
        .sensoryFeedback(trigger: didAppear) { _, _ in
            switch info.severity {
            case .critical: .error
            case .warning: .warning
            case .info: nil
            }
        }
        .onAppear { didAppear = true }
    }
}

struct SuccessPanel: View {
    let operation: FidoUI.PanelModel.Operation
    /// Wired appends "you can remove your YubiKey"; NFC skips it.
    var wasWired: Bool = false
    let onDismiss: () -> Void
    @State private var didAppear = false

    private var copy: (title: String, subtitle: String) {
        let base: (title: String, subtitle: String) =
            switch operation {
            case .registration:
                (
                    String(localized: "Passkey Created"),
                    String(localized: "Your passkey has been registered.")
                )
            case .authentication:
                (
                    String(localized: "Sign-in Successful"),
                    String(localized: "You have been signed in.")
                )
            }
        let removeLine =
            wasWired ? String(localized: " You can remove your YubiKey.") : ""
        return (base.title, base.subtitle + removeLine)
    }

    var body: some View {
        PanelHeader(
            icon: "checkmark.circle.fill",
            tint: .green,
            title: copy.title,
            subtitle: copy.subtitle,
            subtitleBottomPadding: 0,
            titleIdentifier: "success_title",
            subtitleIdentifier: "success_subtitle"
        )
        .panelPadding()
        .sensoryFeedback(.success, trigger: didAppear)
        .onAppear { didAppear = true }
        .task {
            try? await Task.sleep(for: .seconds(2))
            // `try?` swallows CancellationError — check explicitly so a
            // torn-down view doesn't still fire.
            guard !Task.isCancelled else { return }
            onDismiss()
        }
    }
}

#Preview("Error - Retryable") {
    FidoUI.PanelView(
        model: .preview(
            .error(
                .init(
                    title: "Operation Timed Out",
                    message: "The operation took too long. Please try again.",
                    icon: "clock.badge.xmark.fill",
                    severity: .info
                ),
                onRetry: {},
                onDismiss: {}
            )
        )
    )
    .fidoAlertChrome()
}

#Preview("Error - Non-retryable") {
    FidoUI.PanelView(
        model: .preview(
            .error(
                .init(
                    title: "No Passkeys Found",
                    message:
                        "There are no passkeys registered on this YubiKey.",
                    icon: "person.crop.circle.badge.questionmark.fill",
                    severity: .warning,
                    isRetryable: false
                ),
                onRetry: nil,
                onDismiss: {}
            )
        )
    )
    .fidoAlertChrome()
}

#Preview("Error - Critical") {
    FidoUI.PanelView(
        model: .preview(
            .error(
                .init(
                    title: "YubiKey Locked",
                    message:
                        "Too many incorrect PIN attempts. Your YubiKey is locked and must be reset.",
                    icon: "lock.slash.fill",
                    severity: .critical,
                    isRetryable: false
                ),
                onRetry: nil,
                onDismiss: {}
            )
        )
    )
    .fidoAlertChrome()
}

#Preview("Success - Registration (wired)") {
    FidoUI.PanelView(
        model: .preview(
            .success(operation: .registration, wasWired: true, onDismiss: {})
        )
    )
    .fidoAlertChrome()
}

#Preview("Success - Registration (NFC)") {
    FidoUI.PanelView(
        model: .preview(
            .success(operation: .registration, wasWired: false, onDismiss: {})
        )
    )
    .fidoAlertChrome()
}

#Preview("Success - Authentication (wired)") {
    FidoUI.PanelView(
        model: .preview(
            .success(operation: .authentication, wasWired: true, onDismiss: {}),
            operation: .authentication
        )
    )
    .fidoAlertChrome()
}
