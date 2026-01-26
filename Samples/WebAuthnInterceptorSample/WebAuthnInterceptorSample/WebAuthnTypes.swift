//
//  WebAuthnTypes.swift
//  WebAuthnInterceptorSample
//
//  Types for JSON serialization between browser WebAuthn API and YubiKit SDK.
//

import Foundation
import YubiKit

// MARK: - Request Types (Browser → Swift)

struct CreateRequestWrapper: Decodable {
    let type: String
    let origin: String
    let request: CreateRequest
}

struct CreateRequest: Decodable {
    let rp: RelyingParty
    let user: User
    let challenge: String
    let pubKeyCredParams: [PubKeyCredParams]
    let excludeCredentials: [CredentialDescriptor]?
    let authenticatorSelection: AuthenticatorSelection?
    let attestation: String?
    let extensions: CreateExtensions?

    func clientDataJSON(origin: String) throws -> Data {
        try makeClientDataJSON(type: "webauthn.create", challenge: challenge, origin: origin)
    }
}

struct GetRequestWrapper: Decodable {
    let type: String
    let origin: String
    let request: GetRequest
}

struct GetRequest: Decodable {
    let rpId: String?
    let challenge: String
    let allowCredentials: [CredentialDescriptor]?
    let userVerification: String?
    let extensions: GetExtensions?

    func clientDataJSON(origin: String) throws -> Data {
        try makeClientDataJSON(type: "webauthn.get", challenge: challenge, origin: origin)
    }

    func effectiveRpId(origin: String) -> String {
        rpId ?? hostFromOrigin(origin)
    }
}

// MARK: - Request Components

struct RelyingParty: Decodable {
    let id: String?
    let name: String?

    func effectiveId(origin: String) -> String {
        id ?? hostFromOrigin(origin)
    }
}

struct User: Decodable {
    let id: String
    let name: String?
    let displayName: String?
}

struct PubKeyCredParams: Decodable {
    let type: String?
    let alg: Int
}

struct AuthenticatorSelection: Decodable {
    let requireResidentKey: Bool?
    let residentKey: String?
    let userVerification: String?
}

struct CredentialDescriptor: Decodable {
    let type: String
    let id: String?
    let transports: [String]?

    func toDescriptor() -> WebAuthn.PublicKeyCredential.Descriptor? {
        guard let id else {
            logError("CredentialDescriptor missing id")
            return nil
        }
        guard let data = Data(base64urlDecoding: id) else {
            logError("CredentialDescriptor failed to decode id: \(id)")
            return nil
        }
        return WebAuthn.PublicKeyCredential.Descriptor(id: data)
    }
}

// MARK: - Extension Inputs
//
// When adding new extensions, update these input types and the corresponding
// output types in "Extension Results" section below.

struct CreateExtensions: Decodable {
    let credProtect: Int?
    let hmacCreateSecret: Bool?
    let prf: PRFInput?
    let largeBlob: LargeBlobInput?
}

struct GetExtensions: Decodable {
    let prf: PRFInput?
    let largeBlob: LargeBlobInput?
}

struct PRFInput: Decodable {
    let eval: PRFEval?
}

struct PRFEval: Decodable {
    let first: String  // base64url encoded
    let second: String?
}

struct LargeBlobInput: Decodable {
    let support: String?  // "required" or "preferred" (for makeCredential)
    let read: Bool?  // true to read blob (for getAssertion)
    let write: String?  // base64url encoded data to write (for getAssertion)
}

// MARK: - Response Types (Swift → Browser)
//
// WebKit's Swift-to-JavaScript bridge only supports JSON, which has no binary type.
// The WebAuthn API requires ArrayBuffer for fields like rawId, clientDataJSON, etc.
//
// Solution: Encode binary data as `{"__binary__": "<base64url>"}`. The JS side
// recursively finds these markers and decodes them to ArrayBuffer, without needing
// to know which specific fields are binary.

struct CredentialResponse: Codable {
    let type: String
    let id: String?
    let rawId: BinaryValue?
    let response: AuthenticatorResponse
    let clientExtensionResults: ExtensionResults?
    let authenticatorAttachment: String?

    init(
        clientDataJSON: Data,
        makeCredentialResponse: CTAP2.MakeCredential.Response,
        extensionResults: ExtensionResults? = nil
    ) {
        let credentialId = makeCredentialResponse.authenticatorData.attestedCredentialData?.credentialId
        self.type = "public-key"
        self.id = credentialId?.base64urlEncodedString()
        self.rawId = BinaryValue(credentialId)
        self.response = AuthenticatorResponse(
            clientDataJSON: clientDataJSON,
            makeCredentialResponse: makeCredentialResponse
        )
        self.clientExtensionResults = extensionResults
        self.authenticatorAttachment = "cross-platform"
    }

    init(
        clientDataJSON: Data,
        getAssertionResponse: CTAP2.GetAssertion.Response,
        extensionResults: ExtensionResults? = nil
    ) {
        let credentialId = getAssertionResponse.credential?.id
        self.type = "public-key"
        self.id = credentialId?.base64urlEncodedString()
        self.rawId = BinaryValue(credentialId)
        self.response = AuthenticatorResponse(
            clientDataJSON: clientDataJSON,
            getAssertionResponse: getAssertionResponse
        )
        self.clientExtensionResults = extensionResults
        self.authenticatorAttachment = "cross-platform"
    }
}

struct AuthenticatorResponse: Codable {
    let clientDataJSON: BinaryValue
    let authenticatorData: BinaryValue
    let signature: BinaryValue?
    let userHandle: BinaryValue?
    let transports: [String]?
    let attestationObject: BinaryValue?
    let publicKeyAlgorithm: Int?

    init(clientDataJSON: Data, makeCredentialResponse response: CTAP2.MakeCredential.Response) {
        self.clientDataJSON = BinaryValue(clientDataJSON)
        self.authenticatorData = BinaryValue(response.authenticatorData)
        self.signature = nil
        self.userHandle = nil
        self.transports = ["nfc", "usb"]
        self.attestationObject = BinaryValue(response.attestationObject)
        self.publicKeyAlgorithm =
            response.authenticatorData.attestedCredentialData?.credentialPublicKey.algorithmRawValue
    }

    init(clientDataJSON: Data, getAssertionResponse response: CTAP2.GetAssertion.Response) {
        self.clientDataJSON = BinaryValue(clientDataJSON)
        self.authenticatorData = BinaryValue(response.authenticatorData)
        self.signature = BinaryValue(response.signature)
        self.userHandle = BinaryValue(response.user?.id)
        self.transports = nil
        self.attestationObject = nil
        self.publicKeyAlgorithm = nil
    }
}

// MARK: - Extension Results
//
// Output types for WebAuthn extensions. Update when adding new extensions.
// Supported: credProtect (Int), PRF (PRFOutput), largeBlob (LargeBlobOutput)

struct ExtensionResults: Codable {
    var prf: PRFOutput?
    var hmacCreateSecret: Bool?
    var credProtect: Int?
    var largeBlob: LargeBlobOutput?

    var isEmpty: Bool {
        prf == nil && hmacCreateSecret == nil && credProtect == nil && largeBlob == nil
    }
}

struct PRFOutput: Codable {
    let enabled: Bool?
    let results: PRFSecrets?

    /// From makeCredential result (handles both .enabled and .secrets cases)
    init(_ result: WebAuthn.Extension.PRF.MakeCredentialOperations.Result) {
        switch result {
        case .enabled:
            self.enabled = true
            self.results = nil
        case .secrets(let secrets):
            self.enabled = true
            self.results = PRFSecrets(secrets)
        }
    }

    /// From getAssertion secrets
    init(_ secrets: WebAuthn.Extension.PRF.Secrets) {
        self.enabled = true
        self.results = PRFSecrets(secrets)
    }
}

struct PRFSecrets: Codable {
    let first: BinaryValue
    let second: BinaryValue?

    init(_ secrets: WebAuthn.Extension.PRF.Secrets) {
        self.first = BinaryValue(secrets.first)
        self.second = BinaryValue(secrets.second)
    }
}

struct LargeBlobOutput: Codable {
    let supported: Bool?  // For makeCredential: true if largeBlobKey was returned
    let blob: BinaryValue?  // For getAssertion with read: the decrypted blob
    let written: Bool?  // For getAssertion with write: true if write succeeded

    /// For makeCredential - indicates largeBlob support
    static func supported(_ isSupported: Bool) -> LargeBlobOutput {
        LargeBlobOutput(supported: isSupported, blob: nil, written: nil)
    }

    /// For getAssertion read - returns the blob data
    static func read(_ data: Data?) -> LargeBlobOutput {
        LargeBlobOutput(supported: nil, blob: BinaryValue(data), written: nil)
    }

    /// For getAssertion write - indicates success
    static func written(_ success: Bool) -> LargeBlobOutput {
        LargeBlobOutput(supported: nil, blob: nil, written: success)
    }
}

// MARK: - Binary Encoding

/// Protocol for SDK types with raw binary data that should encode as `{"__binary__": "..."}`.
protocol BinaryEncodable {
    var rawData: Data { get }
}

extension WebAuthn.AuthenticatorData: BinaryEncodable {}
extension WebAuthn.AttestationObject: BinaryEncodable {}

/// Encodes binary data as `{"__binary__": "<base64url>"}` for the JS side to decode to ArrayBuffer.
struct BinaryValue: Codable {
    // swiftlint:disable:next identifier_name
    let __binary__: String

    init(_ data: Data) {
        self.__binary__ = data.base64urlEncodedString()
    }

    init?(_ data: Data?) {
        guard let data else { return nil }
        self.__binary__ = data.base64urlEncodedString()
    }

    init(_ value: some BinaryEncodable) {
        self.__binary__ = value.rawData.base64urlEncodedString()
    }

    init?(_ value: (some BinaryEncodable)?) {
        guard let value else { return nil }
        self.__binary__ = value.rawData.base64urlEncodedString()
    }
}

// MARK: - Base64URL Encoding

extension Data {
    init?(base64urlDecoding string: String) {
        var base64 =
            string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        self.init(base64Encoded: base64)
    }

    func base64urlEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// MARK: - Helpers

private func makeClientDataJSON(type: String, challenge: String, origin: String) throws -> Data {
    let clientData: [String: Any] = [
        "type": type,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    ]
    return try JSONSerialization.data(withJSONObject: clientData)
}

private func hostFromOrigin(_ origin: String) -> String {
    if let url = URL(string: origin), let host = url.host { return host }
    return origin
}

extension COSE.Key {
    var algorithmRawValue: Int? {
        switch self {
        case .ec2(let alg, _, _, _, _): return alg.rawValue
        case .okp(let alg, _, _, _): return alg.rawValue
        case .rsa(let alg, _, _, _): return alg.rawValue
        case .other: return nil
        }
    }
}
