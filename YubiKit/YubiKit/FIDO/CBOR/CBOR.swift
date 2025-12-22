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

public enum CBOR {

    // CBOR major types as defined in RFC 8949
    enum MajorType: UInt8 {
        case unsignedInt = 0
        case negativeInt = 1
        case byteString = 2
        case textString = 3
        case array = 4
        case map = 5
        case simpleOrFloat = 7
    }

    // CBOR simple values (major type 7) supported by CTAP2
    // Note: RFC 8949 also defines undefined (23), but CTAP2 does not use it
    enum SimpleValue: UInt8 {
        case `false` = 20
        case `true` = 21
        case null = 22
    }

    // CBOR additional information values for integer encoding/decoding
    // as defined in RFC 8949 §3
    enum AdditionalInfo: UInt8 {
        case oneByte = 24  // Value follows in 1 byte
        case twoBytes = 25  // Value follows in 2 bytes
        case fourBytes = 26  // Value follows in 4 bytes
        case eightBytes = 27  // Value follows in 8 bytes
    }

    // Protocol for types that can be converted to CBOR.Value
    protocol Encodable {
        func cbor() -> CBOR.Value
    }

    // Protocol for types that can be extracted from CBOR.Value
    protocol Decodable {
        init?(cbor: CBOR.Value)
    }

}

// MARK: - Default Implementations

extension CBOR.Encodable where Self: RawRepresentable, RawValue: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        rawValue.cbor()
    }
}

extension CBOR.Decodable where Self: RawRepresentable, RawValue: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        if let rawValue = RawValue(cbor: cbor), let value: Self = .init(rawValue: rawValue) {
            self = value
        } else {
            return nil
        }
    }
}
