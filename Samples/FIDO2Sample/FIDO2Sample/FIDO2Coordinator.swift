// ================================================================================
// FIDO2Coordinator - Minimal CTAP2 API Demonstration
// ================================================================================
//
// This file demonstrates how to use the YubiKit CTAP2 API for:
//   - makeCredential: Create a new credential on the YubiKey
//   - getAssertion: Authenticate using an existing credential with PRF extension
//
// ================================================================================

import Foundation
import YubiKit
import CryptoKit

// MARK: - Tracing

func trace(_ message: String) {
    print("[TRACE] \(message)")
}

// MARK: - Result Types

struct MakeCredentialResult: Sendable {
    let credentialId: Data
    let publicKey: COSE.Key
    let aaguid: Data
    let attestationFormat: String
    let signCount: UInt32
    let hmacSecretEnabled: Bool
}

struct GetAssertionResult: Sendable {
    let credentialId: Data?
    let signature: Data
    let signCount: UInt32
    let prfFirst: Data?
    let prfSecond: Data?
}

// MARK: - FIDO2 Coordinator

actor FIDO2Coordinator {
    private let pinProvider: @Sendable (String?) async -> String?
    #if os(iOS)
    private let connectionProvider: @Sendable () async throws -> SmartCardConnection
    #else
    private let connectionProvider: @Sendable () async throws -> FIDOConnection
    #endif

    /// Creates a FIDO2Coordinator.
    /// - Parameters:
    ///   - pinProvider: Called when PIN is needed. Receives error message (for retries), returns PIN or nil to cancel.
    ///   - connectionProvider: Called when a new connection is needed (e.g., NFC two-tap flow on iOS).
    #if os(iOS)
    init(
        pinProvider: @escaping @Sendable (String?) async -> String?,
        connectionProvider: @escaping @Sendable () async throws -> SmartCardConnection
    ) {
        self.pinProvider = pinProvider
        self.connectionProvider = connectionProvider
    }
    #else
    init(
        pinProvider: @escaping @Sendable (String?) async -> String?,
        connectionProvider: @escaping @Sendable () async throws -> FIDOConnection
    ) {
        self.pinProvider = pinProvider
        self.connectionProvider = connectionProvider
    }
    #endif

    // Demo constants
    private let rpId = "fido2sample.test"
    private let rpName = "FIDO2 Demo"
    private let userName = "demo@example.com"
    private let userDisplayName = "Demo User"

    // MARK: - PIN Handling

    #if os(iOS)
    private func getPinToken(
        session: CTAP2.Session,
        connection: SmartCardConnection,
        permissions: CTAP2.ClientPin.Permission
    ) async throws -> (session: CTAP2.Session, token: CTAP2.ClientPin.Token?) {
        let info = try await session.getInfo()

        // No PIN required
        guard info.options.clientPin == true else {
            trace("PIN not required")
            return (session, nil)
        }

        trace("PIN required, requesting from user...")

        let isNFC = connection is NFCSmartCardConnection
        if isNFC {
            // iOS NFC: Close connection before PIN entry (two-tap flow)
            await (connection as? NFCSmartCardConnection)?.close(message: "Enter PIN, then tap again")
        }

        var errorMessage: String?
        var currentSession = session
        var currentConnection: SmartCardConnection = connection

        while true {
            guard let pin = await pinProvider(errorMessage) else {
                trace("User cancelled PIN entry")
                throw CancellationError()
            }

            if isNFC {
                // Reconnect via NFC for second tap
                currentConnection = try await connectionProvider()
                currentSession = try await CTAP2.Session.makeSession(connection: currentConnection)
            }

            trace("Verifying PIN...")
            do throws(CTAP2.SessionError) {
                let token = try await currentSession.getPinUVToken(
                    using: .pin(pin),
                    permissions: permissions,
                    rpId: rpId
                )
                trace("PIN verified, token obtained")
                return (currentSession, token)
            } catch {
                if case .ctapError(.pinInvalid, _) = error {
                    trace("Invalid PIN, retrying...")
                    if isNFC {
                        await (currentConnection as? NFCSmartCardConnection)?.close(message: "Invalid PIN, tap again")
                    }
                    errorMessage = "Invalid PIN"
                } else {
                    throw error
                }
            }
        }
    }
    #else
    private func getPinToken(
        session: CTAP2.Session,
        permissions: CTAP2.ClientPin.Permission
    ) async throws -> CTAP2.ClientPin.Token? {
        let info = try await session.getInfo()

        // No PIN required
        guard info.options.clientPin == true else {
            trace("PIN not required")
            return nil
        }

        trace("PIN required, requesting from user...")

        var errorMessage: String?

        while true {
            guard let pin = await pinProvider(errorMessage) else {
                trace("User cancelled PIN entry")
                throw CancellationError()
            }

            trace("Verifying PIN...")
            do throws(CTAP2.SessionError) {
                let token = try await session.getPinUVToken(
                    using: .pin(pin),
                    permissions: permissions,
                    rpId: rpId
                )
                trace("PIN verified, token obtained")
                return token
            } catch {
                if case .ctapError(.pinInvalid, _) = error {
                    trace("Invalid PIN, retrying...")
                    errorMessage = "Invalid PIN"
                } else {
                    throw error
                }
            }
        }
    }
    #endif

    // MARK: - makeCredential

    #if os(iOS)
    func makeCredential(connection: SmartCardConnection) async throws -> MakeCredentialResult {
        trace("=== makeCredential ===")
        trace("RP: \(rpId), User: \(userName)")

        var session = try await CTAP2.Session.makeSession(connection: connection)

        // Get PIN token if needed
        let (activeSession, pinToken) = try await getPinToken(
            session: session,
            connection: connection,
            permissions: .makeCredential
        )
        session = activeSession

        return try await performMakeCredential(session: session, pinToken: pinToken)
    }
    #else
    func makeCredential(connection: FIDOConnection) async throws -> MakeCredentialResult {
        trace("=== makeCredential ===")
        trace("RP: \(rpId), User: \(userName)")

        let session = try await CTAP2.Session.makeSession(connection: connection)

        // Get PIN token if needed
        let pinToken = try await getPinToken(session: session, permissions: .makeCredential)

        return try await performMakeCredential(session: session, pinToken: pinToken)
    }
    #endif

    private func performMakeCredential(session: CTAP2.Session, pinToken: CTAP2.ClientPin.Token?) async throws -> MakeCredentialResult {
        // Build clientDataHash (normally done by browser with server-provided challenge)
        let clientDataHash = Data(SHA256.hash(data: Data.random(count: 32)))

        // Build extensions
        trace("Adding hmac-secret extension (for PRF)")
        let prfExt = try await WebAuthn.Extension.PRF(session: session)

        let extensions: [CTAP2.Extension.MakeCredential.Input] = [
            prfExt.makeCredential.input()
        ]

        // Build parameters
        let params = CTAP2.MakeCredential.Parameters(
            clientDataHash: clientDataHash,
            rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: rpName),
            user: WebAuthn.PublicKeyCredential.UserEntity(
                id: Data.random(count: 16),
                name: userName,
                displayName: userDisplayName
            ),
            pubKeyCredParams: [.es256, .edDSA],
            excludeList: nil,
            extensions: extensions,
            options: CTAP2.MakeCredential.Parameters.Options(rk: true, uv: pinToken == nil)
        )

        // Execute
        trace("Sending makeCredential command... (touch YubiKey)")
        let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value
        trace("Credential created!")

        // Parse response
        let authData = response.attestationObject.authenticatorData
        let attested = authData.attestedCredentialData!

        trace("Credential ID: \(attested.credentialId.hexEncodedString)")
        trace("AAGUID: \(attested.aaguid.hexEncodedString)")

        return MakeCredentialResult(
            credentialId: attested.credentialId,
            publicKey: attested.credentialPublicKey,
            aaguid: attested.aaguid,
            attestationFormat: response.attestationObject.format,
            signCount: authData.signCount,
            hmacSecretEnabled: {
                if let result = try? prfExt.makeCredential.output(from: response) {
                    if case .enabled = result { return true }
                    if case .secrets = result { return true }
                }
                return false
            }()
        )
    }

    // MARK: - getAssertion

    #if os(iOS)
    func getAssertion(connection: SmartCardConnection, credentialId: Data) async throws -> GetAssertionResult {
        trace("=== getAssertion ===")
        trace("RP: \(rpId)")

        var session = try await CTAP2.Session.makeSession(connection: connection)

        // Get PIN token if needed
        let (activeSession, pinToken) = try await getPinToken(
            session: session,
            connection: connection,
            permissions: .getAssertion
        )
        session = activeSession

        return try await performGetAssertion(session: session, credentialId: credentialId, pinToken: pinToken)
    }
    #else
    func getAssertion(connection: FIDOConnection, credentialId: Data) async throws -> GetAssertionResult {
        trace("=== getAssertion ===")
        trace("RP: \(rpId)")

        let session = try await CTAP2.Session.makeSession(connection: connection)

        // Get PIN token if needed
        let pinToken = try await getPinToken(session: session, permissions: .getAssertion)

        return try await performGetAssertion(session: session, credentialId: credentialId, pinToken: pinToken)
    }
    #endif

    private func performGetAssertion(session: CTAP2.Session, credentialId: Data, pinToken: CTAP2.ClientPin.Token?) async throws -> GetAssertionResult {
        // Build clientDataHash (normally done by browser with server-provided challenge)
        let clientDataHash = Data(SHA256.hash(data: Data.random(count: 32)))

        // Build allow list
        let allowList = [WebAuthn.PublicKeyCredential.Descriptor(id: credentialId, transports: nil)]
        trace("Using credential: \(credentialId.hexEncodedString.prefix(16))...")

        // Build PRF extension with random salts
        trace("Adding PRF extension with salt")
        let prfExt = try await WebAuthn.Extension.PRF(session: session)
        let extensions = [try prfExt.getAssertion.input(first: Data.random(count: 32), second: Data.random(count: 32))]

        // Build parameters
        // Note: uv option should be false when using PIN token (PIN already provides UV)
        let params = CTAP2.GetAssertion.Parameters(
            rpId: rpId,
            clientDataHash: clientDataHash,
            allowList: allowList,
            extensions: extensions,
            options: CTAP2.GetAssertion.Parameters.Options(uv: pinToken == nil)
        )

        // Execute
        trace("Sending getAssertion command... (touch YubiKey)")
        let response = try await session.getAssertion(parameters: params, pinToken: pinToken).value
        trace("Assertion received!")

        // Parse PRF output
        let prfOutput = try prfExt.getAssertion.output(from: response)
        if let secrets = prfOutput {
            trace("PRF output 1: \(secrets.first.hexEncodedString)")
            if let second = secrets.second {
                trace("PRF output 2: \(second.hexEncodedString)")
            }
        }

        trace("Sign count: \(response.authenticatorData.signCount)")

        return GetAssertionResult(
            credentialId: response.credential?.id,
            signature: response.signature,
            signCount: response.authenticatorData.signCount,
            prfFirst: prfOutput?.first,
            prfSecond: prfOutput?.second
        )
    }
}

// MARK: - Data Extensions

extension Data {
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Generates random bytes for demo purposes.
    /// Note: In production, challenges MUST come from the server to prevent replay attacks.
    static func random(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return data
    }
}
