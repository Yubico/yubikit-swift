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

// MARK: - Shared Encoding Helpers

extension WebAuthn {

    enum CredentialCodingKeys: String, CodingKey {
        case id, rawId, type, authenticatorAttachment, response, clientExtensionResults
    }

    static func encodeCredentialEnvelope(
        to container: inout KeyedEncodingContainer<CredentialCodingKeys>,
        credentialId: Data
    ) throws {
        let idString = credentialId.base64URLEncodedString()
        try container.encode(idString, forKey: .id)
        try container.encode(idString, forKey: .rawId)
        try container.encode("public-key", forKey: .type)
        try container.encode("cross-platform", forKey: .authenticatorAttachment)
    }
}

// MARK: - Private Helpers

/// Decodes base64url-encoded strings to Data.
private struct Base64URLData: Decodable {
    let data: Data

    init(from decoder: Decoder) throws {
        let string = try decoder.singleValueContainer().decode(String.self)
        guard let data = Data(base64URLEncoded: string) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid base64url string")
            )
        }
        self.data = data
    }
}

/// Decodes milliseconds to Duration.
private struct Milliseconds: Decodable {
    let duration: Duration

    init(from decoder: Decoder) throws {
        let ms = try decoder.singleValueContainer().decode(Int.self)
        duration = .milliseconds(ms)
    }
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
            id: try container.decode(Base64URLData.self, forKey: .id).data,
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
            id: try container.decode(Base64URLData.self, forKey: .id).data,
            transports: transports
        )
    }
}

// MARK: - Registration Options Decodable

extension WebAuthn.Registration.Options: Decodable {

    private enum CodingKeys: String, CodingKey {
        case challenge, rp, user, excludeCredentials, authenticatorSelection
        case attestation, pubKeyCredParams, timeout
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let selection = try container.decodeIfPresent(
            AuthenticatorSelectionCriteria.self,
            forKey: .authenticatorSelection
        )

        self.init(
            challenge: try container.decode(Base64URLData.self, forKey: .challenge).data,
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
            timeout: try container.decodeIfPresent(Milliseconds.self, forKey: .timeout)?.duration
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
        return .preferred
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
        try inner.encode(
            rawAttestationObject.base64URLEncodedString(),
            forKey: .attestationObject
        )
        try inner.encodeIfPresent(clientDataJSON?.base64URLEncodedString(), forKey: .clientDataJSON)
        try inner.encode(
            authenticatorData.rawData.base64URLEncodedString(),
            forKey: .authenticatorData
        )
        try inner.encode(transports.map(\.rawValue), forKey: .transports)
        if let algorithm = publicKey?.algorithm {
            try inner.encode(algorithm.rawValue, forKey: .publicKeyAlgorithm)
        }

        try container.encode([String: String](), forKey: .clientExtensionResults)
    }
}

private enum RegistrationResponseKeys: String, CodingKey {
    case attestationObject, clientDataJSON, authenticatorData, transports, publicKeyAlgorithm
}

// MARK: - Authentication Options Decodable

extension WebAuthn.Authentication.Options: Decodable {

    private enum CodingKeys: String, CodingKey {
        case challenge, rpId, allowCredentials, userVerification, timeout
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            challenge: try container.decode(Base64URLData.self, forKey: .challenge).data,
            rpId: try container.decodeIfPresent(String.self, forKey: .rpId),
            allowCredentials: try container.decodeIfPresent(
                [WebAuthn.CredentialDescriptor].self,
                forKey: .allowCredentials
            ) ?? [],
            userVerification: try container.decodeIfPresent(
                WebAuthn.UserVerificationPreference.self,
                forKey: .userVerification
            ) ?? .preferred,
            timeout: try container.decodeIfPresent(Milliseconds.self, forKey: .timeout)?.duration
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
        try inner.encode(
            rawAuthenticatorData.base64URLEncodedString(),
            forKey: .authenticatorData
        )
        try inner.encodeIfPresent(clientDataJSON?.base64URLEncodedString(), forKey: .clientDataJSON)
        try inner.encode(signature.base64URLEncodedString(), forKey: .signature)
        if let userHandle = user?.id {
            try inner.encode(userHandle.base64URLEncodedString(), forKey: .userHandle)
        }

        try container.encode([String: String](), forKey: .clientExtensionResults)
    }
}

private enum AuthenticationResponseKeys: String, CodingKey {
    case authenticatorData, clientDataJSON, signature, userHandle
}
