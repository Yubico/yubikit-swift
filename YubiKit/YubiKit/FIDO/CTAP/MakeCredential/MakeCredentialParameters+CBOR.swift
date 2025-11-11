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

extension MakeCredentialParameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            1: clientDataHash.cbor(),
            2: rp.cbor(),
            3: user.cbor(),
            4: pubKeyCredParams.cbor(),
        ]

        // Optional parameters
        if let excludeList = excludeList, !excludeList.isEmpty {
            map[5] = excludeList.cbor()
        }

        if let extensions = extensions, !extensions.isEmpty {
            if let extensionsValue: CBOR.Value = try? extensions.decode() {
                map[6] = extensionsValue
            }
        }

        if let options = options {
            map[7] = options.cbor()
        }

        if let pinUvAuthParam = pinUvAuthParam {
            map[8] = pinUvAuthParam.cbor()
        }

        if let pinUvAuthProtocol = pinUvAuthProtocol {
            map[9] = pinUvAuthProtocol.cbor()
        }

        if let enterpriseAttestation = enterpriseAttestation {
            map[10] = enterpriseAttestation.cbor()
        }

        return map.cbor()
    }
}

// MARK: - MakeCredentialParameters.Options + CBOR

extension MakeCredentialParameters.Options: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]

        if let rk = rk {
            map["rk"] = rk.cbor()
        }

        if let uv = uv {
            map["uv"] = uv.cbor()
        }

        return map.cbor()
    }
}

// MARK: - PublicKeyCredentialRPEntity + CBOR

extension PublicKeyCredentialRPEntity: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]

        if let name = name {
            map["name"] = name.cbor()
        }

        return map.cbor()
    }
}

// MARK: - PublicKeyCredentialUserEntity + CBOR

extension PublicKeyCredentialUserEntity: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = ["id": id.cbor()]

        if let name = name {
            map["name"] = name.cbor()
        }

        if let displayName = displayName {
            map["displayName"] = displayName.cbor()
        }

        return map.cbor()
    }
}

// MARK: - PublicKeyCredentialParameters + CBOR

extension PublicKeyCredentialParameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .map(["type": type.cbor(), "alg": alg.cbor()])
    }
}

// MARK: - PublicKeyCredentialDescriptor + CBOR

extension PublicKeyCredentialDescriptor: CBOR.Encodable {
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
