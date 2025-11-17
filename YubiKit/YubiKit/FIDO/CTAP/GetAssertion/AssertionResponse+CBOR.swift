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

// MARK: - AssertionResponse + CBOR

extension AssertionResponse: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Optional: credential (0x01)
        let credential: PublicKeyCredentialDescriptor? = map[.unsignedInt(0x01)]?.cborDecoded()

        // Required: authData (0x02)
        guard let authDataBytes: Data = map[.unsignedInt(0x02)]?.cborDecoded(),
            let authData = AuthenticatorData(data: authDataBytes)
        else {
            return nil
        }

        // Required: signature (0x03)
        guard let signature: Data = map[.unsignedInt(0x03)]?.cborDecoded() else {
            return nil
        }

        // Optional: user (0x04)
        let user: PublicKeyCredentialUserEntity? = map[.unsignedInt(0x04)]?.cborDecoded()

        // Optional: numberOfCredentials (0x05)
        let numberOfCredentials: Int? = map[.unsignedInt(0x05)]?.cborDecoded()

        // Optional: userSelected (0x06)
        let userSelected: Bool? = map[.unsignedInt(0x06)]?.cborDecoded()

        // Optional: largeBlobKey (0x07)
        let largeBlobKey: Data? = map[.unsignedInt(0x07)]?.cborDecoded()

        self.init(
            credential: credential,
            authenticatorData: authData,
            signature: signature,
            user: user,
            numberOfCredentials: numberOfCredentials,
            userSelected: userSelected,
            largeBlobKey: largeBlobKey
        )
    }
}

// MARK: - PublicKeyCredentialDescriptor + CBOR Decoding

extension PublicKeyCredentialDescriptor: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let type = map["type"]?.stringValue,
            let id = map["id"]?.dataValue
        else {
            return nil
        }

        let transports: [String]?
        if let transportsArray = map["transports"]?.arrayValue {
            transports = transportsArray.compactMap { $0.stringValue }
        } else {
            transports = nil
        }

        self.init(type: type, id: id, transports: transports)
    }
}

// MARK: - PublicKeyCredentialUserEntity + CBOR Decoding

extension PublicKeyCredentialUserEntity: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let id = map["id"]?.dataValue else {
            return nil
        }

        let name = map["name"]?.stringValue
        let displayName = map["displayName"]?.stringValue
        self.init(id: id, name: name, displayName: displayName)
    }
}
