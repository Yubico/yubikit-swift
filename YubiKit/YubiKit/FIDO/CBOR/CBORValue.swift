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

extension CBOR {
    // CBOR value representation for CTAP2/FIDO2
    indirect public enum Value: Sendable {
        case unsignedInt(UInt64)  // CBOR major type 0
        case negativeInt(UInt64)  // CBOR major type 1, one's complement
        case byteString(Data)  // CBOR major type 2
        case textString(String)  // CBOR major type 3
        case array([Value])  // CBOR major type 4
        case map([Value: Value])  // CBOR major type 5
        case boolean(Bool)  // CBOR simple value
        case null  // CBOR simple value
    }
}

// MARK: - Convenience Initializers

extension CBOR.Value {
    // Creates a CBOR value from an Int64
    public init(_ value: Int64) {
        if value >= 0 {
            self = .unsignedInt(UInt64(value))
        } else {
            self = .negativeInt(UInt64(-1 - value))
        }
    }

    // Creates a CBOR integer from its actual value
    static func int(_ value: Int) -> CBOR.Value {
        if value >= 0 {
            return .unsignedInt(UInt64(value))
        } else {
            return .negativeInt(UInt64(-1 - value))
        }
    }

    // Creates a CBOR integer from an UInt8 with command / subcommand semantics
    static func command(_ value: UInt8) -> CBOR.Value {
        .unsignedInt(UInt64(value))
    }

    // Creates a CBOR value from a UInt64
    public init(_ value: UInt64) {
        self = .unsignedInt(value)
    }

    // Creates a CBOR value from a String
    public init(_ value: String) {
        self = .textString(value)
    }

    // Creates a CBOR value from Data
    public init(_ value: Data) {
        self = .byteString(value)
    }

    // Creates a CBOR value from a Bool
    public init(_ value: Bool) {
        self = .boolean(value)
    }

    // Creates a CBOR array from an array of values
    public init(_ array: [CBOR.Value]) {
        self = .array(array)
    }

    // Creates a CBOR map from a dictionary with CBOR.Value keys
    public init(_ dict: [CBOR.Value: CBOR.Value]) {
        self = .map(dict)
    }
}

// MARK: - Type-Safe Accessors

extension CBOR.Value {
    // Returns the value as an Int if it represents an integer that fits in Int range
    var intValue: Int? {
        switch self {
        case .unsignedInt(let n) where n <= UInt64(Int.max):
            return Int(n)
        case .negativeInt(let n) where n <= UInt64(Int.max):
            return -1 - Int(n)
        default:
            return nil
        }
    }

    // Returns the value as a UInt64 if it represents an unsigned integer
    var uint64Value: UInt64? {
        if case .unsignedInt(let n) = self {
            return n
        }
        return nil
    }

    // Returns the value as a String if it represents a text string
    var stringValue: String? {
        if case .textString(let s) = self {
            return s
        }
        return nil
    }

    // Returns the value as Data if it represents a byte string
    var dataValue: Data? {
        if case .byteString(let d) = self {
            return d
        }
        return nil
    }

    // Returns the value as an array if it represents a CBOR array
    var arrayValue: [CBOR.Value]? {
        if case .array(let a) = self {
            return a
        }
        return nil
    }

    // Returns the value as a map if it represents a CBOR map
    var mapValue: [CBOR.Value: CBOR.Value]? {
        if case .map(let m) = self {
            return m
        }
        return nil
    }

    // Returns the value as a Bool if it represents a boolean
    var boolValue: Bool? {
        if case .boolean(let b) = self {
            return b
        }
        return nil
    }

    // Returns true if the value is null
    var isNull: Bool {
        if case .null = self {
            return true
        }
        return false
    }

    // Subscript for accessing array elements by index or map values with integer keys
    subscript(index: Int) -> CBOR.Value? {
        switch self {
        case .array(let items):
            guard index >= 0, index < items.count else {
                return nil
            }
            return items[index]
        case .map(let dict):
            return dict[.unsignedInt(UInt64(index))]
        default:
            return nil
        }
    }

    // Generic decode helper that works with any CBOR.Decodable type
    func cborDecoded<T: CBOR.Decodable>() -> T? {
        T(cbor: self)
    }
}

// MARK: - Hashable & Equatable

extension CBOR.Value: Hashable {
    public func hash(into hasher: inout Hasher) {
        // Use the canonical CBOR encoding for hashing
        hasher.combine(self.encode())
    }
}

extension CBOR.Value: Equatable {
    public static func == (lhs: CBOR.Value, rhs: CBOR.Value) -> Bool {
        // Two CBOR values are equal if their canonical encodings are equal
        lhs.encode() == rhs.encode()
    }
}

// MARK: - ExpressibleBy Literal Conformances

extension CBOR.Value: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(Int64(value))
    }
}

extension CBOR.Value: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self.init(value)
    }
}

extension CBOR.Value: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) {
        self.init(value)
    }
}

extension CBOR.Value: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: CBOR.Value...) {
        self = .array(elements)
    }
}

extension CBOR.Value: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (CBOR.Value, CBOR.Value)...) {
        var dict: [CBOR.Value: CBOR.Value] = [:]
        for (key, value) in elements {
            dict[key] = value
        }
        self = .map(dict)
    }
}

extension CBOR.Value: ExpressibleByNilLiteral {
    public init(nilLiteral: ()) {
        self = .null
    }
}

// MARK: - CustomStringConvertible

extension CBOR.Value: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unsignedInt(let n):
            return "\(n)"
        case .negativeInt(let n):
            return "\(-1 - Int64(n))"
        case .byteString(let d):
            return "h'\(d.map { String(format: "%02x", $0) }.joined())'"
        case .textString(let s):
            return "\"\(s)\""
        case .array(let items):
            return "[\(items.map { $0.description }.joined(separator: ", "))]"
        case .map(let dict):
            let pairs = dict.map { "\($0.key): \($0.value)" }.joined(separator: ", ")
            return "{\(pairs)}"
        case .boolean(let b):
            return b ? "true" : "false"
        case .null:
            return "null"
        }
    }
}
