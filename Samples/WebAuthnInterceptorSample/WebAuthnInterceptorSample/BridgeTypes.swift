//
//  BridgeTypes.swift
//  WebAuthnInterceptorSample
//
//  Types for JSON serialization between browser WebAuthn API and YubiKit SDK.
//

import Foundation
import YubiKit

// MARK: - Browser → SDK (Input)

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

struct CreateExtensions: Decodable {
    let credProtect: Int?
    let hmacCreateSecret: Bool?
    let prf: PRFInput?
}

struct GetExtensions: Decodable {
    let prf: PRFInput?
}

struct PRFInput: Decodable {
    let eval: PRFEval?
}

struct PRFEval: Decodable {
    let first: String  // base64url encoded
    let second: String?
}

// MARK: - SDK → Browser (Output)

struct CredentialResponse: Codable {
    let type: String
    let id: String?
    let rawId: String?
    let response: AuthenticatorResponse
    let clientExtensionResults: ExtensionResults?
    let authenticatorAttachment: String?

    init(
        clientDataJSON: Data,
        makeCredentialResponse: CTAP2.MakeCredential.Response,
        extensionResults: ExtensionResults? = nil
    ) {
        let credentialId = makeCredentialResponse.authenticatorData.attestedCredentialData?.credentialId
            .base64urlEncodedString()
        self.type = "public-key"
        self.id = credentialId
        self.rawId = credentialId
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
        let credentialId = getAssertionResponse.credential?.id.base64urlEncodedString()
        self.type = "public-key"
        self.id = credentialId
        self.rawId = credentialId
        self.response = AuthenticatorResponse(
            clientDataJSON: clientDataJSON,
            getAssertionResponse: getAssertionResponse
        )
        self.clientExtensionResults = extensionResults
        self.authenticatorAttachment = "cross-platform"
    }
}

struct AuthenticatorResponse: Codable {
    let clientDataJSON: String
    let authenticatorData: String
    let signature: String?
    let userHandle: String?
    let transports: [String]?
    let attestationObject: String?
    let publicKeyAlgorithm: Int?

    init(clientDataJSON: Data, makeCredentialResponse response: CTAP2.MakeCredential.Response) {
        self.clientDataJSON = clientDataJSON.base64urlEncodedString()
        self.authenticatorData = response.authenticatorData.rawData.base64urlEncodedString()
        self.signature = nil
        self.userHandle = nil
        self.transports = ["nfc", "usb"]
        self.attestationObject = response.attestationObject.rawData.base64urlEncodedString()
        self.publicKeyAlgorithm =
            response.authenticatorData.attestedCredentialData?.credentialPublicKey.algorithmRawValue
    }

    init(clientDataJSON: Data, getAssertionResponse response: CTAP2.GetAssertion.Response) {
        self.clientDataJSON = clientDataJSON.base64urlEncodedString()
        self.authenticatorData = response.authenticatorData.rawData.base64urlEncodedString()
        self.signature = response.signature.base64urlEncodedString()
        self.userHandle = response.user?.id.base64urlEncodedString()
        self.transports = nil
        self.attestationObject = nil
        self.publicKeyAlgorithm = nil
    }
}

struct ExtensionResults: Codable {
    var prf: PRFOutput?
    var hmacCreateSecret: Bool?
    var credProtect: Int?

    var isEmpty: Bool { prf == nil && hmacCreateSecret == nil && credProtect == nil }
}

struct PRFOutput: Codable {
    let enabled: Bool?
    let results: PRFSecrets?

    /// For makeCredential when PRF is just enabled (no hmac-secret-mc)
    init(enabled: Bool) {
        self.enabled = enabled
        self.results = nil
    }

    /// For getAssertion or makeCredential with hmac-secret-mc secrets
    init(first: String, second: String?) {
        self.enabled = true
        self.results = PRFSecrets(first: first, second: second)
    }
}

struct PRFSecrets: Codable {
    let first: String  // base64url encoded
    let second: String?
}

// MARK: - Shared Types

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
            trace("CredentialDescriptor missing id")
            return nil
        }
        guard let data = Data(base64urlDecoding: id) else {
            trace("CredentialDescriptor failed to decode id: \(id)")
            return nil
        }
        return WebAuthn.PublicKeyCredential.Descriptor(id: data)
    }
}

// MARK: - Base64URL

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

// MARK: - COSE.Key Helper

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
