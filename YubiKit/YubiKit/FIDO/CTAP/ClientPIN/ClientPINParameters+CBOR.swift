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

// MARK: - ClientPIN.Parameters + CBOR

extension CTAP2.ClientPIN.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [
            0x01: pinUvAuthProtocol.cbor(),
            0x02: subCommand.cbor(),
        ]
        map[0x03] = keyAgreement?.cbor()
        map[0x04] = pinUvAuthParam?.cbor()
        map[0x05] = newPinEnc?.cbor()
        map[0x06] = pinHashEnc?.cbor()
        map[0x09] = permissions?.cbor()
        map[0x0A] = rpId?.cbor()
        return map.cbor()
    }
}
