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
    private let pinProvider: @Sendable () async -> String?

    // TODO: Add PublicSuffixList integration. For now, we don't validate against PSL.
    private let isPublicSuffix: WebAuthn.PublicSuffixChecker = { _ in false }

    init(pinProvider: @escaping @Sendable () async -> String?) {
        self.pinProvider = pinProvider
    }

    // MARK: - Public API

    func handleCreate(_ data: Data) async throws -> String {
        let request = try JSONDecoder().decode(CreateRequest.self, from: data)

        defer { Task { await closeConnection() } }
        let session = try await makeSession()
        let client = WebAuthn.Client(
            session: session,
            origin: try .init(request.origin),
            isPublicSuffix: isPublicSuffix
        )

        let stream = await client.makeCredential(request.publicKey)
        let response = try await handleStream(stream)
        return String(decoding: try response.toJSON(), as: UTF8.self)
    }

    func handleGet(_ data: Data) async throws -> String {
        let request = try JSONDecoder().decode(GetRequest.self, from: data)

        defer { Task { await closeConnection() } }
        let session = try await makeSession()
        let client = WebAuthn.Client(
            session: session,
            origin: try .init(request.origin),
            isPublicSuffix: isPublicSuffix
        )

        let stream = await client.getAssertion(request.publicKey)
        let response = try await handleStream(stream)
        return String(decoding: try response.toJSON(), as: UTF8.self)
    }

    // MARK: - Stream Handling

    private func handleStream<R: Sendable & Encodable>(
        _ stream: WebAuthn.StatusStream<R>
    ) async throws -> R {
        for try await status in stream {
            switch status {
            case .requestingPIN(let submitPIN):
                let pin = await pinProvider()
                submitPIN(pin)
            case .requestingUV(let useUV):
                useUV(true)
            case .finished(let response):
                return response
            default:
                break
            }
        }
        preconditionFailure("Stream ended without response")
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
