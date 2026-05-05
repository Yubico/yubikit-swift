import SwiftUI

struct WaitingForKeyPanel: View {
    let onCancel: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "key.horizontal.fill",
                title: String(localized: "Insert Your YubiKey"),
                subtitle: String(localized: "Plug in your YubiKey to continue"),
                subtitleBottomPadding: onCancel != nil ? 24 : 0,
                titleIdentifier: "waiting_for_key_title",
                subtitleIdentifier: "waiting_for_key_subtitle"
            )

            if let onCancel {
                SecondaryButton(
                    label: String(localized: "Cancel"),
                    identifier: "waiting_for_key_cancel_button",
                    role: .cancel,
                    action: onCancel
                )
            }
        }
        .panelPadding()
    }
}

struct ProcessingPanel: View {
    var body: some View {
        VStack(spacing: 0) {
            ProgressView()
                .controlSize(.large)
                .padding(.bottom, 16)

            VStack(spacing: 8) {
                Text(String(localized: "Processing..."))
                    .font(.title3.bold())
                    .accessibilityIdentifier("processing_title")

                Text(String(localized: "Don't remove your YubiKey"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("processing_subtitle")
            }
            .accessibilityElement(children: .combine)
        }
        .panelPadding()
    }
}

struct TouchPromptPanel: View {
    let onCancel: () -> Void
    @State private var isPulsing = false

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                Circle()
                    .fill(Color.accentColor.opacity(0.15))
                    .frame(width: 80, height: 80)
                    .scaleEffect(isPulsing ? 1.2 : 1.0)
                    .opacity(isPulsing ? 0.0 : 0.6)
                    .accessibilityHidden(true)

                Image(systemName: "hand.tap.fill")
                    .font(.system(size: 36))
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            }
            .padding(.bottom, 16)

            Text(String(localized: "Touch Your YubiKey"))
                .font(.title3.bold())
                .padding(.bottom, 8)
                .accessibilityIdentifier("touch_prompt_title")

            Text(String(localized: "Touch the flashing sensor on your key"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 24)
                .accessibilityIdentifier("touch_prompt_subtitle")

            SecondaryButton(
                label: String(localized: "Cancel"),
                identifier: "touch_prompt_cancel_button",
                role: .cancel
            ) { onCancel() }
        }
        .panelPadding()
        .onAppear {
            withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                isPulsing = true
            }
        }
        .onDisappear { isPulsing = false }
    }
}

#Preview("Waiting for Key") {
    FidoUI.PanelView(model: .preview(.waitingForKey(onCancel: {})))
        .fidoAlertChrome()
}

#Preview("Waiting for Key - No Cancel") {
    FidoUI.PanelView(model: .preview(.waitingForKey(onCancel: nil)))
        .fidoAlertChrome()
}

#Preview("Processing") {
    FidoUI.PanelView(model: .preview(.processing))
        .fidoAlertChrome()
}

#Preview("Touch Prompt") {
    FidoUI.PanelView(model: .preview(.touch(onCancel: {})))
        .fidoAlertChrome()
}
