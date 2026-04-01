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

// MARK: - Client Data

extension WebAuthn {

    /// Client data for WebAuthn operations.
    ///
    /// Encapsulates the client data hash sent to the authenticator, and optionally
    /// the full `clientDataJSON` for standard WebAuthn flows.
    public struct ClientData: Sendable {
        // MARK: - Internal Implementation

        // This is `nil` for credential provider flows where only the hash is provided.
        internal let clientDataJSON: Data?

        // SHA-256 hash of the client data.
        internal let clientDataHash: Data

        // The origin for this request.
        internal let origin: Origin

        // The effective RP ID for this request.
        internal let rpId: String
    }
}

// MARK: - Public Factory Methods

extension WebAuthn.ClientData {

    /// Creates client data for a standard WebAuthn operation.
    ///
    /// Constructs `clientDataJSON` with proper key ordering per the WebAuthn spec.
    ///
    /// - Parameters:
    ///   - type: The operation type (`"webauthn.create"` or `"webauthn.get"`).
    ///   - challenge: The challenge from the relying party.
    ///   - origin: The origin URL.
    ///   - rpId: The relying party ID.
    ///   - crossOrigin: Whether this is a cross-origin request. If `nil`, the field is omitted.
    public static func webauthn(
        type: String,
        challenge: Data,
        origin: WebAuthn.Origin,
        rpId: String,
        crossOrigin: Bool? = nil
    ) -> WebAuthn.ClientData {
        let json = buildJSON(type: type, challenge: challenge, origin: origin, crossOrigin: crossOrigin)
        let hash = Crypto.Hash.sha256(json)
        return Self(clientDataJSON: json, clientDataHash: hash, origin: origin, rpId: rpId)
    }

    /// Creates client data from a pre-computed hash (credential provider flows).
    ///
    /// - Parameters:
    ///   - hash: The pre-computed SHA-256 hash of the client data.
    ///   - origin: The origin URL.
    ///   - rpId: The relying party ID.
    public static func hash(
        _ hash: Data,
        origin: WebAuthn.Origin,
        rpId: String
    ) -> WebAuthn.ClientData {
        Self(clientDataJSON: nil, clientDataHash: hash, origin: origin, rpId: rpId)
    }
}

// MARK: - Private

extension WebAuthn.ClientData {

    private static func buildJSON(
        type: String,
        challenge: Data,
        origin: WebAuthn.Origin,
        crossOrigin: Bool?
    ) -> Data {
        func escape(_ value: String) -> String {
            let data = try! JSONSerialization.data(withJSONObject: value, options: .fragmentsAllowed)
            return String(decoding: data, as: UTF8.self)
        }
        // Key ordering per WebAuthn spec: type, challenge, origin, crossOrigin
        var json =
            "{" + #""type":"# + escape(type)
            + #","challenge":"# + escape(challenge.base64URLEncodedString())
            + #","origin":"# + escape(origin.stringValue)
        if let crossOrigin {
            json += ",\"crossOrigin\":" + String(crossOrigin)
        }
        json += "}"
        return Data(json.utf8)
    }
}
