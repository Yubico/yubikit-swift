/// Receives WebAuthn requests from JS, delegates to WebAuthn.Client.

import Foundation
import YubiKit

// MARK: - Request Types

struct CreateRequest: Decodable {
    let origin: String
    let publicKey: WebAuthn.Registration.Options

    enum CodingKeys: String, CodingKey {
        case origin
        case publicKey = "request"
    }
}

struct GetRequest: Decodable {
    let origin: String
    let publicKey: WebAuthn.Authentication.Options

    enum CodingKeys: String, CodingKey {
        case origin
        case publicKey = "request"
    }
}

// MARK: - WebAuthnHandler

actor WebAuthnHandler {

    private var connection: (any Connection)?
    private let pinProvider: WebAuthn.PINProvider

    // TODO: Add PublicSuffixList integration. For now, we don't validate against PSL.
    private let isPublicSuffix: WebAuthn.PublicSuffixChecker = { _ in false }

    init(pinProvider: @escaping WebAuthn.PINProvider) {
        self.pinProvider = pinProvider
    }

    // MARK: - Public API

    // TODO: iOS NFC needs two-tap flow (close for PIN UI, reconnect). Works on macOS USB only.
    func handleCreate(_ data: Data) async throws -> String {
        let request = try JSONDecoder().decode(CreateRequest.self, from: data)

        defer { Task { await closeConnection() } }
        let session = try await makeSession()
        let client = WebAuthn.Client(
            session: session,
            origin: try .init(request.origin),
            pinProvider: pinProvider,
            isPublicSuffix: isPublicSuffix
        )

        let response = try await client.makeCredential(request.publicKey).value
        return String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    }

    func handleGet(_ data: Data) async throws -> String {
        let request = try JSONDecoder().decode(GetRequest.self, from: data)

        defer { Task { await closeConnection() } }
        let session = try await makeSession()
        let client = WebAuthn.Client(
            session: session,
            origin: try .init(request.origin),
            pinProvider: pinProvider,
            isPublicSuffix: isPublicSuffix
        )

        let response = try await client.getAssertion(request.publicKey).value
        return String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    }

    // MARK: - Connection Management

    #if os(iOS)
    private func makeSession(alertMessage: String = "Tap your YubiKey") async throws -> CTAP2.Session {
        let conn = try await NFCSmartCardConnection(alertMessage: alertMessage)
        connection = conn
        return try await CTAP2.Session.makeSession(connection: conn)
    }
    #else
    private func makeSession() async throws -> CTAP2.Session {
        let conn = try await HIDFIDOConnection()
        connection = conn
        return try await CTAP2.Session.makeSession(connection: conn)
    }
    #endif

    private func closeConnection(message: String? = nil) async {
        #if os(iOS)
        if let nfc = connection as? NFCSmartCardConnection {
            await nfc.close(message: message)
        } else {
            await connection?.close(error: nil)
        }
        #else
        await connection?.close(error: nil)
        #endif
        connection = nil
    }
}
