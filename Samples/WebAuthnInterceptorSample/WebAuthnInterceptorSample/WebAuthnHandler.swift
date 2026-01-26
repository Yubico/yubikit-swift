/// Receives WebAuthn requests from JS, manages YubiKey connection and PIN flow,
/// delegates to WebAuthnClientLogic for extension handling, returns responses.

import CryptoKit
import Foundation
import YubiKit

// MARK: - WebAuthnHandler

actor WebAuthnHandler {

    private var connection: (any Connection)?
    private let pinProvider: @Sendable (String?) async -> String?

    init(pinProvider: @escaping @Sendable (String?) async -> String?) {
        self.pinProvider = pinProvider
    }

    // MARK: - Public API

    func handleCreate(_ data: Data) async throws -> String {
        let wrapper = try JSONDecoder().decode(CreateRequestWrapper.self, from: data)
        let request = wrapper.request
        let origin = wrapper.origin
        let rpId = request.rp.effectiveId(origin: origin)

        defer { Task { await closeConnection() } }
        var session = try await makeSession()

        let rpEntity = WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: request.rp.name)
        let userEntity = WebAuthn.PublicKeyCredential.UserEntity(
            id: Data(base64Encoded: request.user.id) ?? Data(),
            name: request.user.name,
            displayName: request.user.displayName
        )

        let pubKeyParams = request.pubKeyCredParams.map { COSE.Algorithm(rawValue: $0.alg) }
        let excludeList = request.excludeCredentials?.compactMap { $0.toDescriptor() }

        let residentKeyRequired =
            request.authenticatorSelection?.residentKey == "required"
            || request.authenticatorSelection?.residentKey == "preferred"
            || request.authenticatorSelection?.requireResidentKey == true
        let options = CTAP2.MakeCredential.Parameters.Options(
            rk: residentKeyRequired,
            uv: request.authenticatorSelection?.userVerification == "required"
        )

        let (activeSession, pinToken) = try await getPinTokenIfNeeded(
            session: session,
            permissions: .makeCredential,
            rpId: rpId
        )
        session = activeSession

        let extState = try await buildCreateExtensions(request: request, session: session)
        let clientDataJSON = try request.clientDataJSON(origin: origin)
        let clientDataHash = Data(SHA256.hash(data: clientDataJSON))

        let params = CTAP2.MakeCredential.Parameters(
            clientDataHash: clientDataHash,
            rp: rpEntity,
            user: userEntity,
            pubKeyCredParams: pubKeyParams,
            excludeList: excludeList,
            extensions: extState.inputs,
            options: options
        )

        let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value
        let extensionResults = try extractCreateExtensionResults(state: extState, response: response)

        let credentials = CredentialResponse(
            clientDataJSON: clientDataJSON,
            makeCredentialResponse: response,
            extensionResults: extensionResults
        )
        let jsonData = try JSONEncoder().encode(credentials)
        return String(data: jsonData, encoding: .utf8) ?? ""
    }

    func handleGet(_ data: Data) async throws -> String {
        let wrapper = try JSONDecoder().decode(GetRequestWrapper.self, from: data)
        let request = wrapper.request
        let origin = wrapper.origin
        let rpId = request.effectiveRpId(origin: origin)

        defer { Task { await closeConnection() } }
        var session = try await makeSession()

        let allowList = request.allowCredentials?.compactMap { $0.toDescriptor() }

        let options = CTAP2.GetAssertion.Parameters.Options(
            uv: request.userVerification == "required"
        )

        let (activeSession, pinToken) = try await getPinTokenIfNeeded(
            session: session,
            permissions: permissionsForGetAssertion(request: request),
            rpId: rpId
        )
        session = activeSession

        let extState = try await buildGetExtensions(request: request, session: session)
        let clientDataJSON = try request.clientDataJSON(origin: origin)
        let clientDataHash = Data(SHA256.hash(data: clientDataJSON))

        let params = CTAP2.GetAssertion.Parameters(
            rpId: rpId,
            clientDataHash: clientDataHash,
            allowList: allowList,
            extensions: extState.inputs,
            options: options
        )

        let response = try await session.getAssertion(parameters: params, pinToken: pinToken).value
        let extensionResults = try await extractGetExtensionResults(
            state: extState,
            response: response,
            session: session,
            pinToken: pinToken
        )

        let credentials = CredentialResponse(
            clientDataJSON: clientDataJSON,
            getAssertionResponse: response,
            extensionResults: extensionResults
        )
        let jsonData = try JSONEncoder().encode(credentials)
        return String(data: jsonData, encoding: .utf8) ?? ""
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

    // MARK: - PIN Flow

    /// Get PIN token if device requires PIN. iOS uses two-tap flow (close NFC, ask PIN, reconnect).
    private func getPinTokenIfNeeded(
        session: CTAP2.Session,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String
    ) async throws -> (session: CTAP2.Session, pinToken: CTAP2.ClientPin.Token?) {
        let info = try await session.getInfo()
        guard info.options.clientPin == true else {
            return (session, nil)
        }

        #if os(iOS)
        await closeConnection(message: "Enter PIN")
        #endif

        var errorMessage: String?
        var currentSession = session
        while true {
            guard let pin = await pinProvider(errorMessage) else {
                throw WebAuthnHandlerError.userCancelled
            }

            #if os(iOS)
            currentSession = try await makeSession(alertMessage: "Tap again to complete")
            #endif

            do throws(CTAP2.SessionError) {
                let token = try await currentSession.getPinUVToken(
                    using: .pin(pin),
                    permissions: permissions,
                    rpId: rpId
                )
                return (currentSession, token)
            } catch {
                if case .ctapError(.pinInvalid, _) = error {
                    #if os(iOS)
                    await closeConnection(message: "Invalid PIN")
                    #endif
                    errorMessage = "Invalid PIN. Please try again."
                } else {
                    throw error
                }
            }
        }
    }

}

// MARK: - WebAuthnHandlerError

private enum WebAuthnHandlerError: LocalizedError {
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .userCancelled:
            return "User cancelled the operation"
        }
    }
}
