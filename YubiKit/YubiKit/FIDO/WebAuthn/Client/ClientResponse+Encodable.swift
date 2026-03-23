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

// MARK: - WebAuthn Level 3 toJSON()
//
// Encodable conformance produces JSON matching PublicKeyCredential.toJSON()
// from the WebAuthn Level 3 spec.
// https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

extension WebAuthn.Registration.Response: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WebAuthn.CredentialCodingKeys.self)
        try encodeCredentialEnvelope(to: &container, credentialId: credentialId)

        var inner = container.nestedContainer(keyedBy: ResponseKeys.self, forKey: .response)
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

    private enum ResponseKeys: String, CodingKey {
        case attestationObject, clientDataJSON, authenticatorData, transports, publicKeyAlgorithm
    }
}

extension WebAuthn.Authentication.Response: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WebAuthn.CredentialCodingKeys.self)
        try encodeCredentialEnvelope(to: &container, credentialId: credentialId)

        var inner = container.nestedContainer(keyedBy: ResponseKeys.self, forKey: .response)
        try inner.encode(
            rawAuthenticatorData.base64URLEncodedString(),
            forKey: .authenticatorData
        )
        try inner.encodeIfPresent(clientDataJSON?.base64URLEncodedString(), forKey: .clientDataJSON)
        try inner.encode(signature.base64URLEncodedString(), forKey: .signature)
        if let userHandle {
            try inner.encode(userHandle.base64URLEncodedString(), forKey: .userHandle)
        }

        try container.encode([String: String](), forKey: .clientExtensionResults)
    }

    private enum ResponseKeys: String, CodingKey {
        case authenticatorData, clientDataJSON, signature, userHandle
    }
}

// MARK: - Private

extension WebAuthn {

    enum CredentialCodingKeys: String, CodingKey {
        case id, rawId, type, authenticatorAttachment, response, clientExtensionResults
    }
}

private func encodeCredentialEnvelope(
    to container: inout KeyedEncodingContainer<WebAuthn.CredentialCodingKeys>,
    credentialId: Data
) throws {
    let idString = credentialId.base64URLEncodedString()
    try container.encode(idString, forKey: .id)
    try container.encode(idString, forKey: .rawId)
    try container.encode("public-key", forKey: .type)
    try container.encode("cross-platform", forKey: .authenticatorAttachment)
}
