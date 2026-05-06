// Mock WebAuthn backend for driving E2EScenariosView without real hardware.

import FidoUI
import Foundation

@testable import YubiKit

// `WebAuthn.Backend` requires `: Actor` (CTAP2Backend.swift:25), so the type
// must be an `actor`. Scenario setup is synchronous and runs from outside the
// actor, so callbacks are `nonisolated(unsafe) var` — accept the trade-off
// rather than wrapping every scenario assignment in `await`. Single-threaded
// scenario execution makes this safe in practice.
actor MockWebAuthnBackend: WebAuthn.Backend {

    nonisolated(unsafe) var onGetInfo: (() throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response)!
    nonisolated(unsafe) var onGetUVRetries: (() throws(CTAP2.SessionError) -> Int)!
    nonisolated(unsafe) var onGetPinRetries: (() throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response)!
    nonisolated(unsafe) var onGetPinUVToken:
        ((CTAP2.ClientPin.Method, CTAP2.ClientPin.Permission, String?) throws(CTAP2.SessionError) -> CTAP2.Token)!
    nonisolated(unsafe) var onMakeCredential:
        ((CTAP2.MakeCredential.Parameters) -> CTAP2.StatusStream<CTAP2.MakeCredential.Response>)!
    nonisolated(unsafe) var onGetAssertion:
        ((CTAP2.GetAssertion.Parameters) -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!
    nonisolated(unsafe) var onGetNextAssertion: (() -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!

    var cachedInfo: CTAP2.GetInfo.ImmutableView {
        get async throws(CTAP2.SessionError) { try CTAP2.GetInfo.ImmutableView(onGetInfo()) }
    }

    func getInfo() async throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response {
        try? await Task.sleep(for: .milliseconds(200))
        return try onGetInfo()
    }
    func getUVRetries() async throws(CTAP2.SessionError) -> Int {
        try? await Task.sleep(for: .milliseconds(200))
        return try onGetUVRetries()
    }
    func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        try? await Task.sleep(for: .milliseconds(200))
        return try onGetPinRetries()
    }

    /// `WebAuthn.Backend` requirement: the SDK drives token acquisition
    /// through a stream so it can surface keep-alives during built-in UV.
    /// Scenarios stub `onGetPinUVToken` (the simpler one-shot shape); we
    /// wrap that in a finished-status stream here.
    func getPinUVTokenUpdates(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token> {
        try? await Task.sleep(for: .milliseconds(200))
        do throws(CTAP2.SessionError) {
            let token = try onGetPinUVToken(method, permissions, rpId)
            return .mocked(.finished(token), touchDelay: .zero)
        } catch {
            return .mocked(error: error)
        }
    }

    func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        token: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        onMakeCredential(parameters)
    }

    func getAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        token: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        onGetAssertion(parameters)
    }

    func getNextAssertion() async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        onGetNextAssertion()
    }

    func makePRF() async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }
    func makePRF(
        first: Data,
        second: Data?,
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }
    func makePRF(
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }
    func makeCredProtect(
        level: WebAuthn.Extension.CredProtect.Policy,
        enforce: Bool
    ) async throws(CTAP2.SessionError) -> CTAP2.Extension.CredProtect { fatalError() }
    func makeCredBlob() async throws(CTAP2.SessionError) -> CTAP2.Extension.CredBlob { fatalError() }
    func isMinPinLengthSupported() async throws(CTAP2.SessionError) -> Bool { fatalError() }
    func makeMinPinLength() async throws(CTAP2.SessionError) -> CTAP2.Extension.MinPinLength { fatalError() }
    func makeLargeBlobKey() async throws(CTAP2.SessionError) -> CTAP2.Extension.LargeBlobKey { fatalError() }
    func isLargeBlobSupported() async throws(CTAP2.SessionError) -> Bool { fatalError() }
    func getBlob(key: Data) async throws(CTAP2.SessionError) -> Data? { fatalError() }
    func putBlob(key: Data, data: Data, token: CTAP2.Token) async throws(CTAP2.SessionError) { fatalError() }
    func makePreviewSign() async throws(CTAP2.SessionError) -> CTAP2.Extension.PreviewSign { fatalError() }
    func makeThirdPartyPayment() async throws(CTAP2.SessionError) -> CTAP2.Extension.ThirdPartyPayment {
        fatalError()
    }
}

extension CTAP2.StatusStream {
    /// `touchDelay` is how long the stream sits on `.waitingForUser`
    /// before emitting the terminal status — i.e. how long the touch
    /// prompt stays visible. Default 2.5s mimics a real authenticator
    /// awaiting a finger; pass `.zero` for `getNextAssertion`-style
    /// calls that don't gate on touch.
    static func mocked(
        _ status: CTAP2.Status<R>,
        touchDelay: Duration = .milliseconds(2500)
    ) -> Self {
        .init { continuation in
            Task {
                continuation.yield(.processing)
                try? await Task.sleep(for: .milliseconds(400))
                continuation.yield(.waitingForUser(cancel: {}))
                try? await Task.sleep(for: touchDelay)
                continuation.yield(status)
            }
        }
    }

    static func mocked(error: CTAP2.SessionError) -> Self {
        .init { continuation in
            Task {
                continuation.yield(.processing)
                try? await Task.sleep(for: .milliseconds(200))
                continuation.yield(error: error)
            }
        }
    }
}

// MARK: - Response stubs

extension CTAP2.GetInfo.Response {
    static func stub(
        maxCredentialIdLength: UInt? = nil,
        maxCredentialCountInList: UInt? = nil,
        clientPin: Bool = false,
        userVerification: Bool = false,
        pinUvAuthToken: Bool = false,
        forcePinChange: Bool? = nil
    ) -> Self {
        var optionsMap: [CBOR.Value: CBOR.Value] = [
            .textString("up"): .boolean(true),
            .textString("rk"): .boolean(true),
        ]
        if clientPin { optionsMap[.textString("clientPin")] = .boolean(true) }
        if userVerification { optionsMap[.textString("uv")] = .boolean(true) }
        if pinUvAuthToken { optionsMap[.textString("pinUvAuthToken")] = .boolean(true) }
        let options: CTAP2.GetInfo.Options = CBOR.Value.map(optionsMap).cborDecoded()!

        return Self(
            versions: [.fido2_1],
            aaguid: CTAP2.GetInfo.AAGUID(rawValue: Data(repeating: 0, count: 16))!,
            extensions: [],
            options: options,
            maxMsgSize: 1200,
            pinUVAuthProtocols: [.v2],
            maxCredentialCountInList: maxCredentialCountInList,
            maxCredentialIdLength: maxCredentialIdLength,
            transports: [.usb],
            algorithms: [.es256],
            maxSerializedLargeBlobArray: nil,
            forcePinChange: forcePinChange,
            minPinLength: nil,
            firmwareVersion: nil,
            maxCredBlobLength: nil,
            maxRPIDsForSetMinPinLength: nil,
            preferredPlatformUVAttempts: nil,
            uvModality: nil,
            certifications: [:],
            remainingDiscoverableCredentials: nil,
            vendorPrototypeConfigCommands: nil,
            attestationFormats: [],
            uvCountSinceLastPinEntry: nil,
            longTouchForReset: nil,
            encIdentifier: nil,
            transportsForReset: [],
            pinComplexityPolicy: nil,
            pinComplexityPolicyURL: nil,
            maxPINLength: nil,
            encCredStoreState: nil,
            authenticatorConfigCommands: nil
        )
    }
}

extension CTAP2.GetAssertion.Response {
    static func stub(
        credentialId: Data,
        user: WebAuthn.User? = nil,
        numberOfCredentials: Int? = nil
    ) -> Self {
        var authData = Data(repeating: 0, count: 32)
        authData.append(0x01)
        authData.append(contentsOf: [0, 0, 0, 1])
        return Self(
            credential: WebAuthn.CredentialDescriptor(id: credentialId),
            authenticatorData: WebAuthn.AuthenticatorData(data: authData)!,
            signature: Data([0x30, 0x44]),
            user: user,
            numberOfCredentials: numberOfCredentials,
            userSelected: nil,
            largeBlobKey: nil
        )
    }
}

extension CTAP2.MakeCredential.Response {
    /// Minimal attested authenticator data: 32-byte rpIdHash, flags with
    /// `attestedCredentialData` bit set, counter, AAGUID, credentialIdLength,
    /// credentialId, and a COSE-encoded ES256 public key (constants are fine
    /// for UI-only tests — we never verify the signature).
    static func stub(credentialId: Data) -> Self {
        let rpIdHash = Data(repeating: 0, count: 32)
        let flags: UInt8 = 0b0100_0101  // UP | UV | AT
        let counter = Data([0, 0, 0, 1])
        let aaguid = Data(repeating: 0xAA, count: 16)
        let credIdLen = UInt16(credentialId.count)
        let credIdLenBytes = Data([UInt8(credIdLen >> 8), UInt8(credIdLen & 0xFF)])

        // COSE_Key: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x/y = 32 zero bytes.
        let coseKey: CBOR.Value = .map([
            .unsignedInt(1): .unsignedInt(2),
            .unsignedInt(3): .negativeInt(6),
            .negativeInt(0): .unsignedInt(1),
            .negativeInt(1): .byteString(Data(repeating: 0, count: 32)),
            .negativeInt(2): .byteString(Data(repeating: 0, count: 32)),
        ])

        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(counter)
        authData.append(aaguid)
        authData.append(credIdLenBytes)
        authData.append(credentialId)
        authData.append(coseKey.encode())

        return Self(
            attestationObject: WebAuthn.AttestationObject(
                format: "none",
                statementCBOR: .map([:]),
                authenticatorData: WebAuthn.AuthenticatorData(data: authData)!
            ),
            enterpriseAttestation: nil,
            largeBlobKey: nil,
            unsignedExtensionOutputs: nil
        )
    }
}

extension WebAuthn.User {
    static func stub(
        id: Data = Data([0xFF]),
        name: String = "user@example.com",
        displayName: String = "User"
    ) -> Self {
        Self(id: id, name: name, displayName: displayName)
    }
}

extension WebAuthn.Client {
    static func mocked(
        backend: WebAuthn.Backend,
        origin: String = "https://example.com"
    ) throws -> WebAuthn.Client {
        WebAuthn.Client(
            backend: backend,
            origin: try WebAuthn.Origin(origin),
            allowedExtensions: .standard,
            isPublicSuffix: { _ in false }
        )
    }
}

/// Configurable callback bag that test scenarios plug into `FidoUI.Session`'s
/// `setPIN`/`changePIN` closures via ``makeMockedFidoUI``. Setters run from
/// scenario setup (MainActor); reads happen from the FidoUI session closures
/// which are also MainActor (Presenter is MainActor-bound). `nonisolated(unsafe)`
/// avoids `await` ceremony at the setup site — same trade-off as
/// ``MockWebAuthnBackend``'s actor properties. Defaults are no-ops so a
/// scenario that exercises only one path doesn't have to set the other.
final class MockPINSetupBackend {
    nonisolated(unsafe) var onSetPIN: (String) async throws -> Void = { _ in }
    nonisolated(unsafe) var onChangePIN: (String, String) async throws -> Void = { _, _ in }
}
