// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

// MARK: - JSON Convenience Methods

extension WebAuthn.Registration.Options {
    /// Parses registration options from JSON data received from a relying party.
    /// Accepts the bare `PublicKeyCredentialCreationOptions` JSON or the
    /// `{"publicKey": {...}}` envelope passed to `navigator.credentials.create()`.
    public static func from(json data: Data) throws -> Self {
        try decodeOptions(from: data)
    }
}

extension WebAuthn.Registration.Response {
    /// Encodes this response as JSON to send to a relying party.
    public func toJSON() throws -> Data {
        try JSONEncoder().encode(self)
    }
}

extension WebAuthn.Authentication.Options {
    /// Parses authentication options from JSON data received from a relying party.
    /// Accepts the bare `PublicKeyCredentialRequestOptions` JSON or the
    /// `{"publicKey": {...}}` envelope passed to `navigator.credentials.get()`.
    public static func from(json data: Data) throws -> Self {
        try decodeOptions(from: data)
    }
}

extension WebAuthn.Authentication.Response {
    /// Encodes this response as JSON to send to a relying party.
    public func toJSON() throws -> Data {
        try JSONEncoder().encode(self)
    }
}

// MARK: - Shared Encoding Helpers

extension WebAuthn {

    enum CredentialCodingKeys: String, CodingKey {
        case id, rawId, type, authenticatorAttachment, response, clientExtensionResults
    }

    static func encodeCredentialEnvelope(
        to container: inout KeyedEncodingContainer<CredentialCodingKeys>,
        credentialId: Data
    ) throws {
        try container.encodeBase64URL(credentialId, forKey: .id)
        try container.encodeBase64URL(credentialId, forKey: .rawId)
        try container.encode("public-key", forKey: .type)
        try container.encode("cross-platform", forKey: .authenticatorAttachment)
    }
}

// MARK: - Private Helpers

/// Decodes milliseconds to Duration.
private struct Milliseconds: Decodable {
    let duration: Duration

    init(from decoder: Decoder) throws {
        let ms = try decoder.singleValueContainer().decode(Int.self)
        duration = .milliseconds(ms)
    }
}

// MARK: - Options Envelope

private func decodeOptions<T: Decodable>(from data: Data) throws -> T {
    let decoder = JSONDecoder()
    do {
        return try decoder.decode(PublicKeyEnvelope<T>.self, from: data).publicKey
    } catch DecodingError.keyNotFound(let key, let context)
        where key.stringValue == "publicKey" && context.codingPath.isEmpty
    {
        return try decoder.decode(T.self, from: data)
    }
}

private struct PublicKeyEnvelope<T: Decodable>: Decodable {
    let publicKey: T
}

// MARK: - Entity Decodable

extension WebAuthn.RelyingParty: Decodable {

    private enum CodingKeys: String, CodingKey {
        case id, name
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try container.decode(String.self, forKey: .id),
            name: try container.decodeIfPresent(String.self, forKey: .name)
        )
    }
}

extension WebAuthn.User: Decodable {

    private enum CodingKeys: String, CodingKey {
        case id, name, displayName
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try container.decodeBase64URL(forKey: .id),
            name: try container.decodeIfPresent(String.self, forKey: .name),
            displayName: try container.decodeIfPresent(String.self, forKey: .displayName)
        )
    }
}

extension WebAuthn.CredentialDescriptor: Decodable {

    private enum CodingKeys: String, CodingKey {
        case type, id, transports
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let transports: Set<WebAuthn.Transport>?
        if let strings = try container.decodeIfPresent([String].self, forKey: .transports) {
            transports = Set(strings.map { WebAuthn.Transport(rawValue: $0) })
        } else {
            transports = nil
        }
        self.init(
            type: try container.decodeIfPresent(String.self, forKey: .type) ?? "public-key",
            id: try container.decodeBase64URL(forKey: .id),
            transports: transports
        )
    }
}

// MARK: - Registration Options Decodable

extension WebAuthn.Registration.Options: Decodable {

    private enum CodingKeys: String, CodingKey {
        case challenge, rp, user, excludeCredentials, authenticatorSelection
        case attestation, pubKeyCredParams, timeout, extensions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let selection = try container.decodeIfPresent(
            AuthenticatorSelectionCriteria.self,
            forKey: .authenticatorSelection
        )

        self.init(
            challenge: try container.decodeBase64URL(forKey: .challenge),
            rp: try container.decode(WebAuthn.RelyingParty.self, forKey: .rp),
            user: try container.decode(WebAuthn.User.self, forKey: .user),
            excludeCredentials: try container.decodeIfPresent(
                [WebAuthn.CredentialDescriptor].self,
                forKey: .excludeCredentials
            ) ?? [],
            residentKey: Self.resolveResidentKey(from: selection),
            userVerification: selection?.userVerification ?? .preferred,
            attestation: try container.decodeIfPresent(
                WebAuthn.AttestationPreference.self,
                forKey: .attestation
            ) ?? .none,
            pubKeyCredParams: try Self.decodePubKeyCredParams(from: container),
            timeout: try container.decodeIfPresent(Milliseconds.self, forKey: .timeout)?.duration,
            extensions: try container.decodeIfPresent(
                WebAuthn.Extension.RegistrationInputs.self,
                forKey: .extensions
            )
        )
    }

    private static func resolveResidentKey(
        from selection: AuthenticatorSelectionCriteria?
    ) -> WebAuthn.ResidentKeyPreference {
        if let residentKey = selection?.residentKey {
            return residentKey
        } else if selection?.requireResidentKey == true {
            return .required
        }
        return .discouraged
    }

    private static func decodePubKeyCredParams(
        from container: KeyedDecodingContainer<CodingKeys>
    ) throws -> [COSE.Algorithm] {
        guard
            let params = try container.decodeIfPresent(
                [PubKeyCredParam].self,
                forKey: .pubKeyCredParams
            )
        else {
            return [.es256, .edDSA, .rs256]
        }
        return params.map(\.alg)
    }
}

private struct AuthenticatorSelectionCriteria: Decodable {
    let residentKey: WebAuthn.ResidentKeyPreference?
    let requireResidentKey: Bool?
    let userVerification: WebAuthn.UserVerificationPreference?
}

private struct PubKeyCredParam: Decodable {
    let alg: COSE.Algorithm

    private enum CodingKeys: String, CodingKey {
        case alg
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawValue = try container.decode(Int.self, forKey: .alg)
        alg = COSE.Algorithm(rawValue: rawValue)
    }
}

// MARK: - Registration Response Encodable
//
// Encodable conformance produces JSON matching PublicKeyCredential.toJSON()
// from the WebAuthn Level 3 spec.
// https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

extension WebAuthn.Registration.Response: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WebAuthn.CredentialCodingKeys.self)
        try WebAuthn.encodeCredentialEnvelope(to: &container, credentialId: credentialId)

        var inner = container.nestedContainer(keyedBy: RegistrationResponseKeys.self, forKey: .response)
        try inner.encodeBase64URL(rawAttestationObject, forKey: .attestationObject)
        try inner.encodeBase64URLIfPresent(clientDataJSON, forKey: .clientDataJSON)
        try inner.encodeBase64URL(rawAuthenticatorData, forKey: .authenticatorData)
        try inner.encode(transports.map(\.rawValue), forKey: .transports)
        if let pk = PublicKey(cose: publicKey) {
            try inner.encodeBase64URL(pk.spki, forKey: .publicKey)
        }
        if let algorithm = publicKey.algorithm {
            try inner.encode(algorithm.rawValue, forKey: .publicKeyAlgorithm)
        }

        try container.encode(clientExtensionResults, forKey: .clientExtensionResults)
    }
}

private enum RegistrationResponseKeys: String, CodingKey {
    case attestationObject, clientDataJSON, authenticatorData, transports, publicKey, publicKeyAlgorithm
}

// MARK: - Authentication Options Decodable

extension WebAuthn.Authentication.Options: Decodable {

    private enum CodingKeys: String, CodingKey {
        case challenge, rpId, allowCredentials, userVerification, timeout, extensions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            challenge: try container.decodeBase64URL(forKey: .challenge),
            rpId: try container.decodeIfPresent(String.self, forKey: .rpId),
            allowCredentials: try container.decodeIfPresent(
                [WebAuthn.CredentialDescriptor].self,
                forKey: .allowCredentials
            ) ?? [],
            userVerification: try container.decodeIfPresent(
                WebAuthn.UserVerificationPreference.self,
                forKey: .userVerification
            ) ?? .preferred,
            timeout: try container.decodeIfPresent(Milliseconds.self, forKey: .timeout)?.duration,
            extensions: try container.decodeIfPresent(
                WebAuthn.Extension.AuthenticationInputs.self,
                forKey: .extensions
            )
        )
    }
}

// MARK: - Authentication Response Encodable
//
// Encodable conformance produces JSON matching PublicKeyCredential.toJSON()
// from the WebAuthn Level 3 spec.
// https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

extension WebAuthn.Authentication.Response: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WebAuthn.CredentialCodingKeys.self)
        try WebAuthn.encodeCredentialEnvelope(to: &container, credentialId: credentialId)

        var inner = container.nestedContainer(keyedBy: AuthenticationResponseKeys.self, forKey: .response)
        try inner.encodeBase64URL(rawAuthenticatorData, forKey: .authenticatorData)
        try inner.encodeBase64URLIfPresent(clientDataJSON, forKey: .clientDataJSON)
        try inner.encodeBase64URL(signature, forKey: .signature)
        if let userHandle = user?.id {
            try inner.encodeBase64URL(userHandle, forKey: .userHandle)
        }

        try container.encode(clientExtensionResults, forKey: .clientExtensionResults)
    }
}

private enum AuthenticationResponseKeys: String, CodingKey {
    case authenticatorData, clientDataJSON, signature, userHandle
}
