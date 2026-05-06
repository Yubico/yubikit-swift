import SwiftUI

/// `pulse: true` makes the icon breathe to draw attention back to the key.
struct PanelHeader: View {
    let icon: String
    var tint: Color = .accentColor
    var pulse: Bool = false
    let title: String
    var subtitle: String? = nil
    var subtitleBottomPadding: CGFloat = 24
    var titleIdentifier: String? = nil
    var subtitleIdentifier: String? = nil

    @State private var isPulsing = false

    var body: some View {
        VStack(spacing: 0) {
            Image(systemName: icon)
                .font(.system(size: 36))
                .foregroundStyle(tint)
                .scaleEffect(pulse && isPulsing ? 1.1 : 1.0)
                .opacity(pulse && isPulsing ? 0.7 : 1.0)
                .accessibilityHidden(true)
                .padding(.bottom, 16)
                .onAppear {
                    guard pulse else { return }
                    withAnimation(.easeInOut(duration: 1.0).repeatForever(autoreverses: true)) {
                        isPulsing = true
                    }
                }
                .onDisappear { isPulsing = false }

            Text(title)
                .font(.title3.bold())
                .padding(.bottom, 8)
                .accessibilityIdentifierIfPresent(titleIdentifier)

            if let subtitle {
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, subtitleBottomPadding)
                    .accessibilityIdentifierIfPresent(subtitleIdentifier)
            }
        }
    }
}

struct PrimaryButton: View {
    let label: String
    let identifier: String
    var disabled: Bool = false
    var isLoading: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                // Keep the label in layout so width/height don't shrink
                // when the spinner takes over.
                Text(label)
                    .frame(maxWidth: .infinity)
                    .opacity(isLoading ? 0 : 1)
                if isLoading {
                    ProgressView()
                        .controlSize(.small)
                        .tint(.white)
                }
            }
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        // Stay visually enabled while loading so iOS keeps the prominent
        // tint (the white spinner is invisible against the disabled fill);
        // block taps via hit-testing instead.
        .disabled(disabled)
        .allowsHitTesting(!isLoading)
        .accessibilityIdentifier(identifier)
    }
}

struct SecondaryButton: View {
    let label: String
    let identifier: String
    var role: ButtonRole? = nil
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) {
            Text(label).frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
        .keyboardShortcut(role == .cancel ? .cancelAction : nil)
        .accessibilityIdentifier(identifier)
    }
}

struct CancelButton: View {
    var label: String = String(localized: "Cancel")
    let identifier: String
    let action: () -> Void

    var body: some View {
        Button(label, role: .cancel, action: action)
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier(identifier)
    }
}

extension View {
    func panelPadding() -> some View {
        padding(.horizontal, 24).padding(.vertical, 32)
    }

    /// iOS 26+ uses the system scroll edge effect; older targets get a
    /// static gradient mask.
    @ViewBuilder
    func scrollEdgeFade(isScrollable: Bool) -> some View {
        if #available(iOS 26.0, macOS 26.0, *) {
            self.scrollEdgeEffectStyle(.soft, for: .all)
        } else if isScrollable {
            self.mask(
                LinearGradient(
                    stops: [
                        .init(color: .clear, location: 0),
                        .init(color: .black, location: 0.05),
                        .init(color: .black, location: 0.95),
                        .init(color: .clear, location: 1),
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
        } else {
            self
        }
    }
}

func retriesText(_ retries: Int) -> String {
    retries == 1
        ? String(localized: "1 attempt remaining")
        : String(localized: "\(retries) attempts remaining")
}

/// Two-line slot stays reserved when message is nil so the panel doesn't
/// grow when validation toggles in/out.
struct ValidationText: View {
    let message: String?
    let isError: Bool
    var identifier: String? = nil

    var body: some View {
        Text(message ?? " ")
            .font(.caption)
            .foregroundStyle(isError ? .red : .secondary)
            .multilineTextAlignment(.center)
            .lineLimit(2, reservesSpace: true)
            .padding(.bottom, 8)
            .accessibilityLabel(
                isError ? String(localized: "Error: \(message ?? "")") : (message ?? "")
            )
            .accessibilityIdentifierIfPresent(message == nil ? nil : identifier)
            .accessibilityHidden(message == nil)
    }
}

extension View {
    /// Avoid `accessibilityIdentifier(x ?? "")` — an empty-string id is
    /// hard to spot in tests.
    @ViewBuilder
    func accessibilityIdentifierIfPresent(_ identifier: String?) -> some View {
        if let identifier {
            self.accessibilityIdentifier(identifier)
        } else {
            self
        }
    }
}

#Preview("PanelHeader - Default") {
    VStack(spacing: 0) {
        PanelHeader(
            icon: "key.horizontal.fill",
            title: "Insert Your YubiKey",
            subtitle: "Plug in your YubiKey to continue"
        )
    }
    .panelPadding()
    .frame(width: 360)
}

#Preview("PanelHeader - Success Tint") {
    VStack(spacing: 0) {
        PanelHeader(
            icon: "checkmark.circle.fill",
            tint: .green,
            title: "Passkey Created",
            subtitle: "You can now sign in with this YubiKey"
        )
    }
    .panelPadding()
    .frame(width: 360)
}

#Preview("PanelHeader - No Subtitle") {
    VStack(spacing: 0) {
        PanelHeader(
            icon: "touchid",
            title: "Touch Sensor"
        )
    }
    .panelPadding()
    .frame(width: 360)
}

#Preview("PrimaryButton") {
    VStack(spacing: 16) {
        PrimaryButton(label: "Continue", identifier: "continue") {}
        PrimaryButton(label: "Disabled", identifier: "disabled", disabled: true) {}
    }
    .panelPadding()
    .frame(width: 360)
}

#Preview("SecondaryButton") {
    VStack(spacing: 16) {
        SecondaryButton(label: "Use PIN Instead", identifier: "use_pin") {}
        SecondaryButton(label: "Cancel", identifier: "cancel", role: .cancel) {}
    }
    .panelPadding()
    .frame(width: 360)
}

#Preview("CancelButton") {
    VStack(spacing: 16) {
        PrimaryButton(label: "Continue", identifier: "continue") {}
        CancelButton(identifier: "cancel") {}
    }
    .panelPadding()
    .frame(width: 360)
}
