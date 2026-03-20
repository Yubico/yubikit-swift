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

// MARK: - Extension Identifier + CBOR

extension CTAP2.Extension.Identifier: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .textString(value)
    }
}

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
            var extMap: [CBOR.Value: CBOR.Value] = [:]
            for ext in extensions {
                for (id, value) in ext.encode() {
                    extMap[id.cbor()] = value
                }
            }
            map[6] = .map(extMap)
        }
        var optionsMap: [CBOR.Value: CBOR.Value] = [:]
        if rk { optionsMap["rk"] = true.cbor() }
        optionsMap["uv"] = uv?.cbor()
        if !optionsMap.isEmpty { map[7] = optionsMap.cbor() }
        map[8] = pinUVAuthParam?.cbor()
        map[9] = pinUVAuthProtocol?.cbor()
        map[10] = enterpriseAttestation?.cbor()
        return map.cbor()
    }
}

// MARK: - COSE.Algorithm + CBOR

extension COSE.Algorithm: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        ["type": "public-key".cbor(), "alg": rawValue.cbor()].cbor()
    }
}
