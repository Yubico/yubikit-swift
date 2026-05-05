import SwiftUI

struct CredentialPickerPanel: View {
    let credentials: [FidoUI.PanelModel.Credential]
    let serviceName: String
    let onSelect: (Int) -> Void
    let onCancel: () -> Void

    @ScaledMetric(relativeTo: .body) private var rowHeight: CGFloat = 50
    private let maxVisibleRows = 3

    private var listHeight: CGFloat {
        rowHeight * CGFloat(min(credentials.count, maxVisibleRows))
    }

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "person.badge.key.fill",
                title: String(localized: "Choose a Passkey"),
                subtitle: String(
                    localized: "Select a passkey for \(serviceName) (\(credentials.count) available)"
                ),
                subtitleBottomPadding: 16,
                titleIdentifier: "credential_picker_title",
                subtitleIdentifier: "credential_picker_subtitle"
            )

            ScrollView {
                // Eager VStack — with 1–10 credentials, LazyVStack
                // sometimes renders only the first row.
                VStack(spacing: 6) {
                    ForEach(Array(credentials.enumerated()), id: \.element.id) { index, credential in
                        Button {
                            onSelect(index)
                        } label: {
                            CredentialRow(credential: credential)
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("credential_row_\(index)")
                    }
                }
            }
            .scrollBounceBehavior(.always)
            .frame(height: listHeight)
            .clipShape(.rect(cornerRadius: 8))
            .scrollEdgeFade(isScrollable: credentials.count > maxVisibleRows)
            .padding(.bottom, 16)

            CancelButton(identifier: "credential_picker_cancel_button") { onCancel() }
        }
        .panelPadding()
    }
}

private struct CredentialRow: View {
    let credential: FidoUI.PanelModel.Credential

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(credential.name)
                    .font(.body)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                if let displayName = credential.displayName,
                    !displayName.isEmpty
                {
                    Text(displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08), in: .rect(cornerRadius: 8))
        .contentShape(.rect(cornerRadius: 8))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(credentialLabel)
    }

    private var credentialLabel: String {
        if let displayName = credential.displayName,
            !displayName.isEmpty
        {
            return "\(credential.name), \(displayName)"
        }
        return credential.name
    }
}

#Preview("Credential Picker") {
    FidoUI.PanelView(
        model: .preview(
            .credentialPicker(
                [
                    .init(
                        id: Data([1]),
                        name: "user@example.com",
                        displayName: "Alice"
                    ),
                    .init(
                        id: Data([2]),
                        name: "admin@example.com",
                        displayName: "Bob"
                    ),
                ],
                onSelect: { _ in },
                onCancel: {}
            )
        )
    )
    .fidoAlertChrome()
}

#Preview("Credential Picker - Single") {
    FidoUI.PanelView(
        model: .preview(
            .credentialPicker(
                [
                    .init(
                        id: Data([1]),
                        name: "user@example.com",
                        displayName: "Alice Johnson"
                    )
                ],
                onSelect: { _ in },
                onCancel: {}
            ),
            operation: .authentication
        )
    )
    .fidoAlertChrome()
}

#Preview("Credential Picker - Many") {
    FidoUI.PanelView(
        model: .preview(
            .credentialPicker(
                [
                    .init(id: Data([1]), name: "alice@example.com", displayName: "Alice"),
                    .init(id: Data([2]), name: "bob@example.com", displayName: "Bob"),
                    .init(id: Data([3]), name: "charlie@example.com", displayName: "Charlie"),
                    .init(id: Data([4]), name: "diana@example.com", displayName: "Diana"),
                    .init(id: Data([5]), name: "eve@example.com", displayName: "Eve"),
                    .init(id: Data([6]), name: "frank@example.com", displayName: nil),
                ],
                onSelect: { _ in },
                onCancel: {}
            ),
            operation: .authentication
        )
    )
    .fidoAlertChrome()
}
