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

// MARK: - Integer Types

extension Int: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let value = cbor.intValue else {
            return nil
        }
        self = value
    }
}

extension Int8: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= Int(Int8.min), intValue <= Int(Int8.max) else {
            return nil
        }
        self = Int8(intValue)
    }
}

extension Int16: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= Int(Int16.min), intValue <= Int(Int16.max) else {
            return nil
        }
        self = Int16(intValue)
    }
}

extension Int32: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= Int(Int32.min), intValue <= Int(Int32.max) else {
            return nil
        }
        self = Int32(intValue)
    }
}

extension Int64: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue else {
            return nil
        }
        self = Int64(intValue)
    }
}

extension UInt: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= 0 else {
            return nil
        }
        self = UInt(intValue)
    }
}

extension UInt8: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= 0, intValue <= Int(UInt8.max) else {
            return nil
        }
        self = UInt8(intValue)
    }
}

extension UInt16: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= 0, intValue <= Int(UInt16.max) else {
            return nil
        }
        self = UInt16(intValue)
    }
}

extension UInt32: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let intValue = cbor.intValue, intValue >= 0, intValue <= Int(UInt32.max) else {
            return nil
        }
        self = UInt32(intValue)
    }
}

extension UInt64: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let value = cbor.uint64Value else {
            return nil
        }
        self = value
    }
}

// MARK: - String

extension String: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let value = cbor.stringValue else {
            return nil
        }
        self = value
    }
}

// MARK: - Bool

extension Bool: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let value = cbor.boolValue else {
            return nil
        }
        self = value
    }
}

// MARK: - Data

extension Data: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let value = cbor.dataValue else {
            return nil
        }
        self = value
    }
}

// MARK: - Array

extension Array: CBOR.Decodable where Element: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let arrayValue = cbor.arrayValue else {
            return nil
        }
        let decoded = arrayValue.map { $0.cborDecoded() as Element? }
        guard decoded.allSatisfy({ $0 != nil }) else {
            return nil
        }
        self = decoded.compactMap { $0 }
    }
}

// MARK: - Dictionary

extension Dictionary: CBOR.Decodable where Key: CBOR.Decodable, Value: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let mapValue = cbor.mapValue else {
            return nil
        }
        let decoded = mapValue.compactMap { (cborKey, cborValue) -> (Key, Value)? in
            guard let key: Key = cborKey.cborDecoded(),
                let value: Value = cborValue.cborDecoded()
            else {
                return nil
            }
            return (key, value)
        }
        guard decoded.count == mapValue.count else {
            return nil
        }
        self = Dictionary(uniqueKeysWithValues: decoded)
    }
}

// MARK: - CBOR.Value itself

extension CBOR.Value: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        self = cbor
    }
}
