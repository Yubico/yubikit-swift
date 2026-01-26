//
//  Bridge.swift
//  WebAuthnInterceptorSample
//
//  Core orchestrator: receives WebAuthn requests from JS, communicates with YubiKey via CTAP2,
//  and returns responses. Handles connection lifecycle, PIN flow, and extension processing.
//

import CryptoKit
import Foundation
import YubiKit

// MARK: - Bridge

actor Bridge {

    private var connection: (any Connection)?
    private let pinProvider: @Sendable (String?) async -> String?

    init(pinProvider: @escaping @Sendable (String?) async -> String?) {
        self.pinProvider = pinProvider
        trace("Bridge initialized")
    }

    // MARK: - Public API

    func handleCreate(_ data: Data) async throws -> String {
        trace("handleCreate: \(String(data: data, encoding: .utf8) ?? "nil")")
        let wrapper = try JSONDecoder().decode(CreateRequestWrapper.self, from: data)
        let request = wrapper.request
        let origin = wrapper.origin
        let rpId = request.rp.effectiveId(origin: origin)
        trace("RP: \(rpId), User: \(request.user.name ?? "nil"), Origin: \(origin)")

        defer { Task { await closeConnection() } }
        var session = try await makeSession()

        let rpEntity = WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: request.rp.name)
        let userEntity = WebAuthn.PublicKeyCredential.UserEntity(
            id: Data(base64urlDecoding: request.user.id) ?? Data(),
            name: request.user.name,
            displayName: request.user.displayName
        )

        let pubKeyParams = request.pubKeyCredParams.map { COSE.Algorithm(rawValue: $0.alg) }
        let excludeList = request.excludeCredentials?.compactMap { $0.toDescriptor() }
        if let count = excludeList?.count { trace("Exclude list has \(count) credentials") }

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

        trace("Calling makeCredential...")
        let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value

        // Extract extension results
        var extensionResults = ExtensionResults()
        if let credProtect = extState.credProtect, let level = credProtect.output(from: response) {
            trace("credProtect applied with level \(level.rawValue)")
            extensionResults.credProtect = level.rawValue
        }
        if let prf = extState.prf, let prfResult = try prf.makeCredential.output(from: response) {
            trace("PRF extension result received")
            extensionResults.prf = PRFOutput(prfResult)
        }

        let credentials = CredentialResponse(
            clientDataJSON: clientDataJSON,
            makeCredentialResponse: response,
            extensionResults: extensionResults.isEmpty ? nil : extensionResults
        )
        let jsonData = try JSONEncoder().encode(credentials)
        trace("handleCreate completed")
        return String(data: jsonData, encoding: .utf8) ?? ""
    }

    func handleGet(_ data: Data) async throws -> String {
        trace("handleGet: \(String(data: data, encoding: .utf8) ?? "nil")")
        let wrapper = try JSONDecoder().decode(GetRequestWrapper.self, from: data)
        let request = wrapper.request
        let origin = wrapper.origin
        let rpId = request.effectiveRpId(origin: origin)
        trace("RP: \(rpId), Origin: \(origin)")

        defer { Task { await closeConnection() } }
        var session = try await makeSession()

        let allowList = request.allowCredentials?.compactMap { $0.toDescriptor() }
        if let count = allowList?.count { trace("Allow list has \(count) credentials") }

        let options = CTAP2.GetAssertion.Parameters.Options(
            uv: request.userVerification == "required"
        )

        let (activeSession, pinToken) = try await getPinTokenIfNeeded(
            session: session,
            permissions: .getAssertion,
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

        trace("Calling getAssertion...")
        let response = try await session.getAssertion(parameters: params, pinToken: pinToken).value

        // Extract extension results
        var extensionResults = ExtensionResults()
        if let prf = extState.prf, let secrets = try prf.getAssertion.output(from: response) {
            trace("PRF extension returned secrets")
            extensionResults.prf = PRFOutput(secrets)
        }

        let credentials = CredentialResponse(
            clientDataJSON: clientDataJSON,
            getAssertionResponse: response,
            extensionResults: extensionResults.isEmpty ? nil : extensionResults
        )
        let jsonData = try JSONEncoder().encode(credentials)
        trace("handleGet completed")
        return String(data: jsonData, encoding: .utf8) ?? ""
    }

    // MARK: - Connection Management

    #if os(iOS)
    private func makeSession(alertMessage: String = "Tap your YubiKey") async throws -> CTAP2.Session {
        trace("Requesting NFC connection...")
        let conn = try await NFCSmartCardConnection(alertMessage: alertMessage)
        connection = conn
        trace("Connection established, creating CTAP2 session...")
        let session = try await CTAP2.Session.makeSession(connection: conn)
        trace("CTAP2 session created")
        return session
    }
    #else
    private func makeSession() async throws -> CTAP2.Session {
        trace("Waiting for USB HID FIDO connection...")
        let conn = try await HIDFIDOConnection()
        connection = conn
        trace("Connection established, creating CTAP2 session...")
        let session = try await CTAP2.Session.makeSession(connection: conn)
        trace("CTAP2 session created")
        return session
    }
    #endif

    private func closeConnection(message: String? = nil) async {
        trace("Closing connection" + (message.map { ": \($0)" } ?? ""))
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
        trace("Device clientPin option: \(String(describing: info.options.clientPin))")

        guard info.options.clientPin == true else {
            return (session, nil)
        }

        #if os(iOS)
        await closeConnection(message: "Enter PIN")
        #endif

        var errorMessage: String?
        var currentSession = session
        while true {
            trace("Prompting for PIN...")
            guard let pin = await pinProvider(errorMessage) else {
                trace("User cancelled PIN entry")
                throw BridgeError.userCancelled
            }

            #if os(iOS)
            trace("Got PIN, reconnecting...")
            currentSession = try await makeSession(alertMessage: "Tap again to complete")
            #endif

            trace("Obtaining PIN token...")
            do throws(CTAP2.SessionError) {
                let token = try await currentSession.getPinUVToken(
                    using: .pin(pin),
                    permissions: permissions,
                    rpId: rpId
                )
                return (currentSession, token)
            } catch {
                if case .ctapError(.pinInvalid, _) = error {
                    trace("Invalid PIN, retrying...")
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

    // MARK: - Extension Handling
    //
    // Extensions require manual handling: build inputs before CTAP call, extract outputs after.
    // When adding new extensions, update: state structs, build functions, and result extraction.
    // Supported: credProtect, PRF (hmac-secret)

    private struct CreateExtensionState {
        var inputs: [CTAP2.Extension.MakeCredential.Input] = []
        var credProtect: CTAP2.Extension.CredProtect?
        var prf: WebAuthn.Extension.PRF?
    }

    private func buildCreateExtensions(
        request: CreateRequest,
        session: CTAP2.Session
    ) async throws -> CreateExtensionState {
        var state = CreateExtensionState()

        // credProtect extension
        if let credProtectLevel = request.extensions?.credProtect,
            let level = CTAP2.Extension.CredProtect.Level(rawValue: credProtectLevel)
        {
            trace("Adding credProtect extension with level \(credProtectLevel)")
            let credProtect = try await CTAP2.Extension.CredProtect(level: level, session: session)
            state.inputs.append(credProtect.input())
            state.credProtect = credProtect
        }

        // PRF extension (with or without secrets)
        if let prfEval = request.extensions?.prf?.eval,
            let firstData = Data(base64urlDecoding: prfEval.first)
        {
            trace("Adding PRF extension for makeCredential with secrets")
            let prf = try await WebAuthn.Extension.PRF(session: session)
            let secondData = prfEval.second.flatMap { Data(base64urlDecoding: $0) }
            state.inputs.append(try prf.makeCredential.input(first: firstData, second: secondData))
            state.prf = prf
        } else if request.extensions?.hmacCreateSecret == true || request.extensions?.prf != nil {
            trace("Adding PRF extension for makeCredential (enable only)")
            let prf = try await WebAuthn.Extension.PRF(session: session)
            state.inputs.append(prf.makeCredential.input())
            state.prf = prf
        }

        return state
    }

    private struct GetExtensionState {
        var inputs: [CTAP2.Extension.GetAssertion.Input] = []
        var prf: WebAuthn.Extension.PRF?
    }

    private func buildGetExtensions(
        request: GetRequest,
        session: CTAP2.Session
    ) async throws -> GetExtensionState {
        var state = GetExtensionState()

        // PRF extension
        if let prfEval = request.extensions?.prf?.eval,
            let firstData = Data(base64urlDecoding: prfEval.first)
        {
            trace("Adding PRF extension")
            let prf = try await WebAuthn.Extension.PRF(session: session)
            let secondData = prfEval.second.flatMap { Data(base64urlDecoding: $0) }
            state.inputs.append(try prf.getAssertion.input(first: firstData, second: secondData))
            state.prf = prf
        }

        return state
    }
}

// MARK: - BridgeError

enum BridgeError: LocalizedError {
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .userCancelled:
            return "User cancelled the operation"
        }
    }
}

// MARK: - Trace Logging

func trace(_ message: String, file: String = #file, line: Int = #line) {
    let filename = (file as NSString).lastPathComponent
    print("[TRACE] \(filename):\(line) - \(message)")
}
