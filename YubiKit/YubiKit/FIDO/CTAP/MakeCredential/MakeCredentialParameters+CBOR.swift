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

// MARK: - MakeCredentialParameters + CBOR

extension CTAP2.MakeCredential.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            1: clientDataHash.cbor(),
            2: rp.cbor(),
            3: user.cbor(),
            4: pubKeyCredParams.cbor(),
        ]
        if let excludeList = excludeList, !excludeList.isEmpty {
            map[5] = excludeList.cbor()
        }
        if !extensions.isEmpty {
            map[6] = extensions.cbor()
        }
        map[7] = options?.cbor()
        map[8] = pinUVAuthParam?.cbor()
        map[9] = pinUVAuthProtocol?.cbor()
        map[10] = enterpriseAttestation?.cbor()
        return map.cbor()
    }
}

// MARK: - MakeCredentialParameters.Options + CBOR

extension CTAP2.MakeCredential.Parameters.Options: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map["rk"] = rk?.cbor()
        map["uv"] = uv?.cbor()
        return map.cbor()
    }
}

// MARK: - PublicKeyCredential.RPEntity + CBOR

extension PublicKeyCredential.RPEntity: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]
        map["name"] = name?.cbor()
        return map.cbor()
    }
}

// MARK: - PublicKeyCredential.UserEntity + CBOR

extension PublicKeyCredential.UserEntity: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]
        map["name"] = name?.cbor()
        map["displayName"] = displayName?.cbor()
        return map.cbor()
    }
}

// MARK: - COSE.Algorithm + CBOR

extension COSE.Algorithm: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        ["type": "public-key".cbor(), "alg": rawValue.cbor()].cbor()
    }
}

// MARK: - PublicKeyCredential.Descriptor + CBOR

extension PublicKeyCredential.Descriptor: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            "type": type.cbor(),
            "id": id.cbor(),
        ]

        if let transports = transports, !transports.isEmpty {
            map["transports"] = transports.cbor()
        }

        return map.cbor()
    }
}
