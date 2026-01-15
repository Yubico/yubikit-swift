// ================================================================================
// ConnectionManager - Automatic YubiKey Connection Detection
// ================================================================================
//
// Detects wired YubiKey connections automatically:
//   - iOS: USB-C or Lightning via WiredSmartCardConnection
//   - macOS: USB via HIDFIDOConnection
//
// On iOS, if no wired connection is detected, NFC can be requested manually.
//
// ================================================================================

import Foundation
import YubiKit

@MainActor
final class ConnectionManager: ObservableObject {

    static let shared = ConnectionManager()

    /// Currently connected wired YubiKey (USB-C, Lightning, or USB HID)
    #if os(iOS)
    @Published private(set) var wiredConnection: SmartCardConnection?
    #else
    @Published private(set) var wiredConnection: FIDOConnection?
    #endif

    #if os(iOS)
    /// Active NFC connection (iOS only, user-triggered)
    @Published private(set) var nfcConnection: NFCSmartCardConnection?
    #endif

    @Published private(set) var error: Error?

    private var connectionTask: Task<Void, Never>?

    private init() {
        startListening()
    }

    // MARK: - Connection Listening

    private func startListening() {
        connectionTask = Task { @MainActor in
            while !Task.isCancelled {
                do {
                    error = nil
                    guard !Task.isCancelled else { return }

                    #if os(iOS)
                    // iOS: Listen for wired smart card connections (USB-C or Lightning)
                    let connection = try await WiredSmartCardConnection.makeConnection()
                    #else
                    // macOS: Listen for HID FIDO connections (USB)
                    let connection = try await HIDFIDOConnection()
                    #endif

                    guard !Task.isCancelled else { return }
                    trace("Wired connection detected: \(type(of: connection))")
                    wiredConnection = connection

                    // Wait for disconnection
                    let closeError = await connection.waitUntilClosed()
                    trace("Wired connection closed")
                    wiredConnection = nil

                    if let closeError {
                        error = closeError
                    }
                } catch {
                    self.error = error
                }
            }
        }
    }

    // MARK: - NFC (iOS only)

    #if os(iOS)
    /// Request an NFC connection. The connection is published via `nfcConnection`.
    func startNFCConnection(alertMessage: String = "Tap your YubiKey") async throws -> NFCSmartCardConnection {
        error = nil
        let connection = try await NFCSmartCardConnection(alertMessage: alertMessage)
        nfcConnection = connection
        return connection
    }

    func closeNFCConnection(message: String? = nil) async {
        await nfcConnection?.close(message: message)
        nfcConnection = nil
    }
    #endif

    // MARK: - Connection Type

    var connectionType: String? {
        if let conn = wiredConnection {
            return connectionTypeString(for: conn)
        }
        #if os(iOS)
        if nfcConnection != nil {
            return "NFC"
        }
        #endif
        return nil
    }

    #if os(iOS)
    private func connectionTypeString(for connection: SmartCardConnection) -> String {
        if connection is LightningSmartCardConnection {
            return "Lightning"
        }
        if connection is USBSmartCardConnection {
            return "USB"
        }
        return "Wired"
    }
    #else
    private func connectionTypeString(for connection: FIDOConnection) -> String {
        return "USB"
    }
    #endif
}
