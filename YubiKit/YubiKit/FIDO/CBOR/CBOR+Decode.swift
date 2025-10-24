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

extension Data {

    // Decodes CBOR data into a CBOR.Value
    func decode() throws(CBOR.Error) -> CBOR.Value {
        var offset = 0
        let value = try decodeValue(from: self, offset: &offset)

        guard offset == self.count else {
            throw CBOR.Error.extraneousData
        }

        return value
    }

    // Decodes a single CBOR value from data at a specific offset
    private func decodeValue(from data: Data, offset: inout Int) throws(CBOR.Error) -> CBOR.Value {
        guard offset < data.count else {
            throw CBOR.Error.unexpectedEndOfData
        }

        let head = data[offset]
        offset += 1

        let majorTypeRaw = head >> 5
        let additionalInfo = head & 0b11111

        guard let majorType = CBOR.MajorType(rawValue: majorTypeRaw) else {
            throw CBOR.Error.unsupportedMajorType(majorTypeRaw)
        }

        switch majorType {
        case .unsignedInt:
            let value = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            return .unsignedInt(value)

        case .negativeInt:
            let value = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            return .negativeInt(value)

        case .byteString:
            let length = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            guard offset + Int(length) <= data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }
            let bytes = data[offset..<(offset + Int(length))]
            offset += Int(length)
            return .byteString(Data(bytes))

        case .textString:
            let length = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            guard offset + Int(length) <= data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }
            let bytes = data[offset..<(offset + Int(length))]
            offset += Int(length)
            guard let string = String(data: Data(bytes), encoding: .utf8) else {
                throw CBOR.Error.invalidUTF8
            }
            return .textString(string)

        case .array:
            let count = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            var items: [CBOR.Value] = []
            items.reserveCapacity(Int(count))
            for _ in 0..<count {
                items.append(try decodeValue(from: data, offset: &offset))
            }
            return .array(items)

        case .map:
            let count = try decodeInt(additionalInfo: additionalInfo, from: data, offset: &offset)
            var dict: [CBOR.Value: CBOR.Value] = [:]
            dict.reserveCapacity(Int(count))
            for _ in 0..<count {
                let key = try decodeValue(from: data, offset: &offset)
                let value = try decodeValue(from: data, offset: &offset)
                dict[key] = value
            }
            return .map(dict)

        case .simpleOrFloat:
            guard let simpleValue = CBOR.SimpleValue(rawValue: additionalInfo) else {
                throw CBOR.Error.unsupportedSimpleValue(additionalInfo)
            }
            switch simpleValue {
            case .false:
                return .boolean(false)
            case .true:
                return .boolean(true)
            case .null:
                return .null
            }
        }
    }

    // Decodes an integer value based on additional info
    private func decodeInt(
        additionalInfo: UInt8,
        from data: Data,
        offset: inout Int
    ) throws(CBOR.Error) -> UInt64 {
        if additionalInfo < 24 {
            return UInt64(additionalInfo)
        }

        guard let info = CBOR.AdditionalInfo(rawValue: additionalInfo) else {
            throw CBOR.Error.invalidAdditionalInfo(additionalInfo)
        }

        switch info {
        case .oneByte:
            guard offset < data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }

            let value = data[offset]

            offset += 1
            return UInt64(value)

        case .twoBytes:
            guard offset + 2 <= data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }

            let value = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])

            offset += 2
            return UInt64(value)

        case .fourBytes:
            guard offset + 4 <= data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }

            let value =
                UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])

            offset += 4
            return UInt64(value)

        case .eightBytes:
            guard offset + 8 <= data.count else {
                throw CBOR.Error.unexpectedEndOfData
            }

            let value =
                UInt64(data[offset]) << 56
                | UInt64(data[offset + 1]) << 48
                | UInt64(data[offset + 2]) << 40
                | UInt64(data[offset + 3]) << 32
                | UInt64(data[offset + 4]) << 24
                | UInt64(data[offset + 5]) << 16
                | UInt64(data[offset + 6]) << 8
                | UInt64(data[offset + 7])

            offset += 8
            return value
        }
    }
}
