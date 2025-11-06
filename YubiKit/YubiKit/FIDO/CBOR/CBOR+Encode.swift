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

extension CBOR.Value {

    // Encodes a CBOR value into its canonical byte representation
    func encode() -> Data {
        var output = Data()
        encodeValue(self, to: &output)
        return output
    }

    // Encodes a CBOR value into an existing data buffer
    private func encodeValue(_ value: CBOR.Value, to output: inout Data) {
        switch value {
        case .unsignedInt(let n):
            encodeInt(n, majorType: .unsignedInt, to: &output)

        case .negativeInt(let n):
            encodeInt(n, majorType: .negativeInt, to: &output)

        case .byteString(let data):
            encodeInt(UInt64(data.count), majorType: .byteString, to: &output)
            output.append(data)

        case .textString(let string):
            let utf8 = Data(string.utf8)
            encodeInt(UInt64(utf8.count), majorType: .textString, to: &output)
            output.append(utf8)

        case .array(let items):
            encodeInt(UInt64(items.count), majorType: .array, to: &output)
            for item in items {
                encodeValue(item, to: &output)
            }

        case .map(let dict):
            encodeMap(dict, to: &output)

        case .boolean(let bool):
            let simpleValue: CBOR.SimpleValue = bool ? .true : .false
            output.append(0xe0 | simpleValue.rawValue)

        case .null:
            output.append(0xe0 | CBOR.SimpleValue.null.rawValue)
        }
    }

    // Encodes an integer with a specific CBOR major type using minimum bytes (canonical encoding)
    private func encodeInt(_ value: UInt64, majorType: CBOR.MajorType, to output: inout Data) {
        let head = majorType.rawValue << 5

        if value <= 23 {
            // Encode in the head byte itself
            output.append(head | UInt8(value))
        } else if value <= 0xff {
            // 1-byte value
            output.append(head | CBOR.AdditionalInfo.oneByte.rawValue)
            output.append(UInt8(value))
        } else if value <= 0xffff {
            // 2-byte value
            output.append(head | CBOR.AdditionalInfo.twoBytes.rawValue)
            var bigEndian = UInt16(value).bigEndian
            output.append(Data(bytes: &bigEndian, count: 2))
        } else if value <= 0xffff_ffff {
            // 4-byte value
            output.append(head | CBOR.AdditionalInfo.fourBytes.rawValue)
            var bigEndian = UInt32(value).bigEndian
            output.append(Data(bytes: &bigEndian, count: 4))
        } else {
            // 8-byte value
            output.append(head | CBOR.AdditionalInfo.eightBytes.rawValue)
            var bigEndian = value.bigEndian
            output.append(Data(bytes: &bigEndian, count: 8))
        }
    }

    // Encodes a map with canonical key ordering
    private func encodeMap(_ dict: [CBOR.Value: CBOR.Value], to output: inout Data) {
        encodeInt(UInt64(dict.count), majorType: .map, to: &output)

        // Encode keys and values separately, then sort by key bytes
        var entries: [(keyBytes: Data, valueBytes: Data)] = []

        for (key, value) in dict {
            var keyData = Data()
            var valueData = Data()
            encodeValue(key, to: &keyData)
            encodeValue(value, to: &valueData)
            entries.append((keyData, valueData))
        }

        // Canonical ordering: lexicographical comparison of encoded key bytes
        entries.sort { $0.keyBytes.lexicographicallyPrecedes($1.keyBytes) }

        // Write sorted entries
        for entry in entries {
            output.append(entry.keyBytes)
            output.append(entry.valueBytes)
        }
    }
}
