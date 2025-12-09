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

// MARK: - CBOR Encoding for Parameters

extension CTAP2.ClientPin.GetRetries.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        return map.cbor()
    }
}

extension CTAP2.ClientPin.GetKeyAgreement.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        return map.cbor()
    }
}

extension CTAP2.ClientPin.SetPin.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        map[0x03] = keyAgreement.cbor()
        map[0x04] = pinUVAuthParam.cbor()
        map[0x05] = newPinEnc.cbor()
        return map.cbor()
    }
}

extension CTAP2.ClientPin.ChangePin.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        map[0x03] = keyAgreement.cbor()
        map[0x04] = pinUVAuthParam.cbor()
        map[0x05] = newPinEnc.cbor()
        map[0x06] = pinHashEnc.cbor()
        return map.cbor()
    }
}

extension CTAP2.ClientPin.GetToken.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        map[0x03] = keyAgreement.cbor()
        map[0x06] = pinHashEnc.cbor()
        return map.cbor()
    }
}

extension CTAP2.ClientPin.GetTokenUsingUV.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        map[0x03] = keyAgreement.cbor()
        map[0x09] = permissions.cbor()
        map[0x0A] = rpId?.cbor()
        return map.cbor()
    }
}

extension CTAP2.ClientPin.GetUVRetries.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        return map.cbor()
    }
}

extension CTAP2.ClientPin.GetTokenWithPermissions.Parameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[0x01] = pinUVAuthProtocol.cbor()
        map[0x02] = CBOR.Value.command(Self.commandCode)
        map[0x03] = keyAgreement.cbor()
        map[0x06] = pinHashEnc.cbor()
        map[0x09] = permissions.cbor()
        map[0x0A] = rpId?.cbor()
        return map.cbor()
    }
}

// MARK: - CBOR Decoding for Responses

extension CTAP2.ClientPin.GetRetries.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let retries = map[.int(0x03)]?.intValue
        else {
            return nil
        }
        self.retries = retries
        self.powerCycleState = map[.int(0x04)]?.boolValue ?? false
    }
}

extension CTAP2.ClientPin.GetKeyAgreement.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let keyAgreementCbor = map[.int(0x01)],
            let keyAgreement = COSE.Key(cbor: keyAgreementCbor)
        else {
            return nil
        }
        self.keyAgreement = keyAgreement
    }
}

extension CTAP2.ClientPin.GetToken.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let token = map[.int(0x02)]?.dataValue
        else {
            return nil
        }
        self.pinUVAuthToken = token
    }
}

extension CTAP2.ClientPin.GetUVRetries.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let retries = map[.int(0x05)]?.intValue
        else {
            return nil
        }
        self.retries = retries
    }
}
