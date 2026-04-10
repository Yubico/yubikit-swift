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

// MARK: - Entity CBOR Conformance

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

// MARK: - Attestation Format CBOR Conformance

extension WebAuthn.AttestationFormat: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let string: String = cbor.cborDecoded() else {
            return nil
        }
        self.init(rawValue: string)
    }
}

extension WebAuthn.AttestationFormat: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .textString(rawValue)
    }
}

// MARK: - Attestation Statement CBOR Conformance

extension WebAuthn.AttestationStatement.Packed: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: sig
        guard let sig: Data = map["sig"]?.cborDecoded() else {
            return nil
        }
        self.sig = sig

        // Required: alg
        guard let alg: Int = map["alg"]?.cborDecoded() else {
            return nil
        }
        self.alg = alg

        // Optional: x5c (certificate chain)
        self.x5c = map["x5c"]?.cborDecoded()

        // Optional: ecdaaKeyId (rarely used)
        self.ecdaaKeyId = map["ecdaaKeyId"]?.cborDecoded()
    }
}

extension WebAuthn.AttestationStatement.FIDOU2F: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: sig
        guard let sig: Data = map["sig"]?.cborDecoded() else {
            return nil
        }
        self.sig = sig

        // Required: x5c (certificate chain)
        guard let x5c: [Data] = map["x5c"]?.cborDecoded() else {
            return nil
        }
        self.x5c = x5c
    }
}

extension WebAuthn.AttestationStatement.Apple: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: x5c (certificate chain)
        guard let x5c: [Data] = map["x5c"]?.cborDecoded() else {
            return nil
        }
        self.x5c = x5c
    }
}
