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

extension WebAuthn {

    /// Client data for WebAuthn operations.
    ///
    /// Encapsulates the `clientDataJSON` and provides the hash sent to the authenticator.
    ///
    /// ```swift
    /// let clientData = ClientData.webauthn(
    ///     type: "webauthn.create",
    ///     challenge: challenge,
    ///     origin: origin,
    ///     rpId: "example.com"
    /// )
    /// ```
    public struct ClientData: Sendable {

        /// Raw client data JSON bytes.
        public let clientDataJSON: Data

        /// The origin for this request.
        public let origin: Origin

        /// The effective RP ID for this request.
        public let rpId: String

        /// SHA-256 hash of the client data JSON.
        public var hash: Data {
            Crypto.Hash.sha256(clientDataJSON)
        }

        init(clientDataJSON: Data, origin: Origin, rpId: String) {
            self.clientDataJSON = clientDataJSON
            self.origin = origin
            self.rpId = rpId
        }
    }
}

// MARK: - Factory Methods

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
        return Self(clientDataJSON: json, origin: origin, rpId: rpId)
    }

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
            json += #","crossOrigin":"# + String(crossOrigin)
        }
        json += "}"
        return Data(json.utf8)
    }
}
