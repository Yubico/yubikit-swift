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

    /// Namespace for credential registration types.
    public enum Registration {

        /// Options for registering a new passkey credential.
        ///
        /// Equivalent to `PublicKeyCredentialCreationOptions` in the WebAuthn spec.
        public struct Options: Sendable {
            public let challenge: Data
            public let rp: WebAuthn.RelyingParty
            public let user: WebAuthn.User
            public let excludeCredentials: [WebAuthn.CredentialDescriptor]
            public let residentKey: WebAuthn.ResidentKeyPreference
            public let userVerification: WebAuthn.UserVerificationPreference
            public let attestation: WebAuthn.AttestationPreference
            public let pubKeyCredParams: [COSE.Algorithm]
            public let timeout: Duration?

            public init(
                challenge: Data,
                rp: WebAuthn.RelyingParty,
                user: WebAuthn.User,
                excludeCredentials: [WebAuthn.CredentialDescriptor] = [],
                residentKey: WebAuthn.ResidentKeyPreference = .preferred,
                userVerification: WebAuthn.UserVerificationPreference = .preferred,
                attestation: WebAuthn.AttestationPreference = .none,
                pubKeyCredParams: [COSE.Algorithm] = [.es256, .edDSA, .rs256],
                timeout: Duration? = nil
            ) {
                self.challenge = challenge
                self.rp = rp
                self.user = user
                self.excludeCredentials = excludeCredentials
                self.residentKey = residentKey
                self.userVerification = userVerification
                self.attestation = attestation
                self.pubKeyCredParams = pubKeyCredParams
                self.timeout = timeout
            }
        }
    }

    /// Namespace for credential authentication types.
    public enum Authentication {

        /// Options for authenticating with an existing passkey credential.
        ///
        /// Equivalent to `PublicKeyCredentialRequestOptions` in the WebAuthn spec.
        public struct Options: Sendable {
            public let challenge: Data
            public let rpId: String?
            public let allowCredentials: [WebAuthn.CredentialDescriptor]
            public let userVerification: WebAuthn.UserVerificationPreference
            public let timeout: Duration?

            public init(
                challenge: Data,
                rpId: String? = nil,
                allowCredentials: [WebAuthn.CredentialDescriptor] = [],
                userVerification: WebAuthn.UserVerificationPreference = .preferred,
                timeout: Duration? = nil
            ) {
                self.challenge = challenge
                self.rpId = rpId
                self.allowCredentials = allowCredentials
                self.userVerification = userVerification
                self.timeout = timeout
            }
        }
    }

    /// Relying Party entity information.
    ///
    /// Identifies the relying party (website or service) that is requesting
    /// credential registration or authentication.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialRpEntity](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity)
    public struct RelyingParty: Sendable {
        /// Relying Party identifier (e.g., "example.com").
        public let id: String

        /// Human-readable relying party name.
        public let name: String?

        public init(id: String, name: String? = nil) {
            self.id = id
            self.name = name
        }
    }

    /// User account entity information.
    ///
    /// Identifies the user account for which a credential is being registered
    /// or that owns an existing credential.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity)
    public struct User: Sendable {
        /// User handle (opaque byte sequence).
        public let id: Data

        /// User identifier (e.g., "alice@example.com").
        public let name: String?

        /// Display name (e.g., "Alice Smith").
        public let displayName: String?

        public init(id: Data, name: String? = nil, displayName: String? = nil) {
            self.id = id
            self.name = name
            self.displayName = displayName
        }
    }

    /// Public key credential descriptor identifying a specific credential.
    ///
    /// Used in `allowList` and `excludeList` parameters to identify credentials
    /// for authentication or exclusion during registration.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialDescriptor](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
    public struct CredentialDescriptor: Sendable, Hashable {
        /// Credential type (always "public-key" for FIDO2).
        public let type: String

        /// Credential ID (opaque byte sequence).
        public let id: Data

        /// Optional transports hint.
        public let transports: Set<Transport>?

        public init(type: String = "public-key", id: Data, transports: Set<Transport>? = nil) {
            self.type = type
            self.id = id
            self.transports = transports
        }
    }

    public enum ResidentKeyPreference: String, Sendable, Decodable {
        case required, preferred, discouraged
    }

    public enum UserVerificationPreference: String, Sendable, Decodable {
        case required, preferred, discouraged
    }

    public enum AttestationPreference: String, Sendable, Decodable {
        case none, indirect, direct, enterprise
    }
}

// MARK: - CBOR Conformance

extension WebAuthn.RelyingParty: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]
        map["name"] = name?.cbor()
        return map.cbor()
    }
}

extension WebAuthn.User: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]
        map["name"] = name?.cbor()
        map["displayName"] = displayName?.cbor()
        return map.cbor()
    }
}

extension WebAuthn.CredentialDescriptor: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            "type": type.cbor(),
            "id": id.cbor(),
        ]
        if let transports, !transports.isEmpty {
            map["transports"] = Array(transports).map(\.rawValue).cbor()
        }
        return map.cbor()
    }
}

extension WebAuthn.RelyingParty: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let id = map["id"]?.stringValue
        else {
            return nil
        }
        let name = map["name"]?.stringValue
        self.init(id: id, name: name)
    }
}

extension WebAuthn.User: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let id = map["id"]?.dataValue
        else {
            return nil
        }
        let name = map["name"]?.stringValue
        let displayName = map["displayName"]?.stringValue
        self.init(id: id, name: name, displayName: displayName)
    }
}

extension WebAuthn.CredentialDescriptor: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let type = map["type"]?.stringValue,
            let id = map["id"]?.dataValue
        else {
            return nil
        }
        let transports: Set<WebAuthn.Transport>?
        if let transportsArray = map["transports"]?.arrayValue {
            let transportValues = transportsArray.compactMap { value -> WebAuthn.Transport? in
                guard let rawValue = value.stringValue else { return nil }
                return WebAuthn.Transport(rawValue: rawValue)
            }
            transports = Set(transportValues)
        } else {
            transports = nil
        }
        self.init(type: type, id: id, transports: transports)
    }
}
