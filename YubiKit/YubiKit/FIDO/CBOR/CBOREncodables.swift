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

extension Int: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

extension Int8: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(Int(self))
    }
}

extension Int16: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(Int(self))
    }
}

extension Int32: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

extension Int64: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(Int(self))
    }
}

extension UInt: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

extension UInt8: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(UInt(self))
    }
}

extension UInt16: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(UInt(self))
    }
}

extension UInt32: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(UInt(self))
    }
}

extension UInt64: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

// MARK: - String

extension String: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

// MARK: - Bool

extension Bool: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

// MARK: - Data

extension Data: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self)
    }
}

// MARK: - Array

extension Array: CBOR.Encodable where Element: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        CBOR.Value(self.map { $0.cbor() })
    }
}

// MARK: - Dictionary

extension Dictionary: CBOR.Encodable where Key: CBOR.Encodable, Value: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var cborDict: [CBOR.Value: CBOR.Value] = [:]
        for (key, value) in self {
            cborDict[key.cbor()] = value.cbor()
        }
        return CBOR.Value(cborDict)
    }
}

// MARK: - Optional

extension Optional: CBOR.Encodable where Wrapped: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        switch self {
        case .none:
            return .null
        case .some(let value):
            return value.cbor()
        }
    }
}

// MARK: - CBOR.Value itself

extension CBOR.Value: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        self
    }
}
