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

// MARK: - CTAP.GetAssertion.Parameters + CBOR

extension CTAP2.GetAssertion.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            1: rpId.cbor(),
            2: clientDataHash.cbor(),
        ]
        if let allowList = allowList, !allowList.isEmpty {
            map[3] = allowList.cbor()
        }
        if let extensions = extensions {
            let extensionsValue = extensions.cbor()
            if case .map(let extensionsMap) = extensionsValue, !extensionsMap.isEmpty {
                map[4] = extensionsValue
            }
        }
        map[5] = options?.cbor()
        map[6] = pinUVAuthParam?.cbor()
        map[7] = pinUVAuthProtocol?.cbor()
        return map.cbor()
    }
}

// MARK: - CTAP.GetAssertion.Parameters.Options + CBOR

extension CTAP2.GetAssertion.Parameters.Options: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map["up"] = up?.cbor()
        map["uv"] = uv?.cbor()
        return map.cbor()
    }
}
