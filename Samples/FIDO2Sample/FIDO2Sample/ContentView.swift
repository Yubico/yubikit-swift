// ================================================================================
// ContentView - Simple FIDO2 Demonstration UI
// ================================================================================

import SwiftUI
import YubiKit

struct ContentView: View {
    @StateObject private var connectionManager = ConnectionManager.shared
    @StateObject private var pinHandler = PINRequestHandler()

    @State private var coordinator: FIDO2Coordinator?
    @State private var isLoading = false
    @State private var credentialId: Data? // Demo: lost on restart. Credential persists on YubiKey.
    @State private var resultAlert: ResultAlert?

    var connectionStatus: String {
        if let type = connectionManager.connectionType {
            return "Connected via \(type)"
        }
        #if os(iOS)
        return "No YubiKey connected"
        #else
        return "Connect YubiKey via USB"
        #endif
    }

    var connectionColor: Color {
        connectionManager.wiredConnection != nil ? .green : .secondary
    }

    var body: some View {
        VStack(spacing: 24) {
            Text("FIDO2 Sample")
                .font(.largeTitle)
                .fontWeight(.bold)

            HStack {
                Circle()
                    .fill(connectionColor)
                    .frame(width: 8, height: 8)
                Text(connectionStatus)
                    .font(.caption)
                    .foregroundColor(connectionColor)
            }

            Spacer()

            // Create Credential button
            Button {
                Task { await createCredential() }
            } label: {
                HStack {
                    if isLoading { ProgressView().controlSize(.small) }
                    Text("Create Credential").frame(width: 200)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isLoading)

            // Authenticate button
            Button {
                Task { await authenticate() }
            } label: {
                HStack {
                    if isLoading { ProgressView().controlSize(.small) }
                    Text("Authenticate with PRF").frame(width: 200)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isLoading || credentialId == nil)

            #if os(iOS)
            if connectionManager.wiredConnection == nil {
                Text("Tap a button to scan with NFC, or plug in your YubiKey")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            #endif

            if credentialId == nil {
                Text("Create a credential first")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding(40)
        .frame(minWidth: 400, minHeight: 300)
        .sheet(isPresented: $pinHandler.isShowingPINEntry) {
            PINEntryView(handler: pinHandler)
        }
        .onAppear {
            setupCoordinator()
        }
        .alert(item: $resultAlert) { alert in
            Alert(title: Text(alert.title), message: Text(alert.message), dismissButton: .default(Text("OK")))
        }
    }

    private func setupCoordinator() {
        coordinator = FIDO2Coordinator(
            pinProvider: { [pinHandler] in await pinHandler.requestPIN(errorMessage: $0) },
            connectionProvider: { [connectionManager] in try await Self.getConnection(using: connectionManager) }
        )
    }

    /// Gets a connection: uses wired if available, otherwise NFC on iOS
    #if os(iOS)
    @MainActor
    private static func getConnection(using connectionManager: ConnectionManager) async throws -> SmartCardConnection {
        // Prefer wired connection if available
        if let wired = connectionManager.wiredConnection {
            trace("Using existing wired connection")
            return wired
        }

        // Fall back to NFC on iOS
        trace("No wired connection, starting NFC...")
        return try await connectionManager.startNFCConnection(alertMessage: "Tap your YubiKey")
    }
    #else
    @MainActor
    private static func getConnection(using connectionManager: ConnectionManager) async throws -> FIDOConnection {
        // Must have wired connection on macOS
        guard let wired = connectionManager.wiredConnection else {
            throw NSError(domain: "FIDO2Sample", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Please connect your YubiKey via USB"
            ])
        }
        trace("Using existing wired connection")
        return wired
    }
    #endif

    private func createCredential() async {
        guard let coordinator else { return }
        isLoading = true
        let usedWired = connectionManager.wiredConnection != nil

        do {
            let connection = try await Self.getConnection(using: connectionManager)
            let result = try await coordinator.makeCredential(connection: connection)
            credentialId = result.credentialId
            resultAlert = ResultAlert(result: result)

            #if os(iOS)
            if !usedWired {
                await connectionManager.closeNFCConnection(message: "Credential created!")
            }
            #endif
        } catch is CancellationError {
            // User cancelled, no alert needed
        } catch {
            resultAlert = ResultAlert(error: error)
            #if os(iOS)
            if !usedWired {
                await connectionManager.closeNFCConnection(message: "Error")
            }
            #endif
        }
        isLoading = false
    }

    private func authenticate() async {
        guard let coordinator, let credentialId else { return }
        isLoading = true
        let usedWired = connectionManager.wiredConnection != nil

        do {
            let connection = try await Self.getConnection(using: connectionManager)
            let result = try await coordinator.getAssertion(connection: connection, credentialId: credentialId)
            resultAlert = ResultAlert(result: result)

            #if os(iOS)
            if !usedWired {
                await connectionManager.closeNFCConnection(message: "Authentication successful!")
            }
            #endif
        } catch is CancellationError {
            // User cancelled, no alert needed
        } catch {
            resultAlert = ResultAlert(error: error)
            #if os(iOS)
            if !usedWired {
                await connectionManager.closeNFCConnection(message: "Error")
            }
            #endif
        }
        isLoading = false
    }
}

// MARK: - Result Alert

private struct ResultAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String

    init(result: MakeCredentialResult) {
        self.title = "Credential Created"
        self.message = """
            PRF Enabled: \(result.hmacSecretEnabled ? "Yes" : "No")
            Credential ID: \(result.credentialId.hexEncodedString.prefix(8))...
            """
    }

    init(result: GetAssertionResult) {
        self.title = "Authentication Successful"
        var lines = ["Sign Count: \(result.signCount)"]
        if let first = result.prfFirst {
            lines.append("PRF Output 1: \(first.hexEncodedString.prefix(8))...")
        }
        if let second = result.prfSecond {
            lines.append("PRF Output 2: \(second.hexEncodedString.prefix(8))...")
        }
        self.message = lines.joined(separator: "\n")
    }

    init(error: Error) {
        self.title = "Error"
        self.message = String(reflecting: error)
    }
}
