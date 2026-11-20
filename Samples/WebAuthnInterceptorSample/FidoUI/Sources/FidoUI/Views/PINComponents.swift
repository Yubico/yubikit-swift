import SwiftUI

struct PINFieldRow<Focus: Hashable>: View {
    let label: String
    let inputIdentifier: String
    @Binding var text: String
    @Binding var isVisible: Bool
    var focus: FocusState<Focus>.Binding
    var focusValue: Focus
    let visibilityToggleIdentifier: String

    var body: some View {
        HStack(spacing: 4) {
            Group {
                if isVisible {
                    TextField(label, text: $text)
                        .accessibilityIdentifier(inputIdentifier)
                } else {
                    SecureField(label, text: $text)
                        .accessibilityIdentifier(inputIdentifier)
                }
            }
            .focused(focus, equals: focusValue)
            .textFieldStyle(.roundedBorder)
            #if os(iOS)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .submitLabel(.continue)
            .frame(minHeight: 44)
            #endif

            Button {
                isVisible.toggle()
            } label: {
                Image(systemName: isVisible ? "eye" : "eye.slash")
                    .foregroundStyle(.secondary)
                    #if os(iOS)
                .frame(width: 44, height: 44)
                .contentShape(.rect)
                    #endif
            }
            .buttonStyle(.plain)
            .accessibilityLabel(
                isVisible
                    ? String(localized: "Hide PIN")
                    : String(localized: "Show PIN")
            )
            .accessibilityIdentifier(visibilityToggleIdentifier)
        }
        .onChange(of: isVisible) { focus.wrappedValue = focusValue }
    }
}

/// Auto-continues after a 2-second hold; tap Continue to short-circuit.
struct PINConfirmationPanel: View {
    let title: String
    let message: String
    let titleIdentifier: String
    let subtitleIdentifier: String
    let continueIdentifier: String
    let onContinue: () -> Void
    @State private var didAppear = false

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "checkmark.circle.fill",
                tint: .green,
                title: title,
                subtitle: message,
                titleIdentifier: titleIdentifier,
                subtitleIdentifier: subtitleIdentifier
            )

            PrimaryButton(
                label: String(localized: "Continue"),
                identifier: continueIdentifier
            ) { onContinue() }
        }
        .panelPadding()
        .sensoryFeedback(.success, trigger: didAppear)
        .onAppear { didAppear = true }
        .task {
            try? await Task.sleep(for: .seconds(2))
            // `try?` swallows CancellationError — check explicitly so a
            // torn-down view doesn't still fire.
            guard !Task.isCancelled else { return }
            onContinue()
        }
    }
}

#if DEBUG
#Preview("PIN Created") {
    FidoUI.PanelView(
        model: .preview(.pinCreated(onContinue: {}))
    )
    .fidoAlertChrome()
}

#Preview("PIN Changed") {
    FidoUI.PanelView(
        model: .preview(.pinChanged(onContinue: {}))
    )
    .fidoAlertChrome()
}
#endif
