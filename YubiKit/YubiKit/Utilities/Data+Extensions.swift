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

    internal var bytes: [UInt8] {
        [UInt8](self)
    }

    internal var uint8: UInt8 {
        get {
            var number: UInt8 = 0
            self.copyBytes(to: &number, count: MemoryLayout<UInt8>.size)
            return number
        }
    }

    internal var uint16: UInt16 {
        get {
            let i16array = self.withUnsafeBytes { $0.load(as: UInt16.self) }
            return i16array
        }
    }

    internal var uint32: UInt32 {
        get {
            let i32array = self.withUnsafeBytes { $0.load(as: UInt32.self) }
            return i32array
        }
    }

    internal var uuid: NSUUID? {
        get {
            var bytes = [UInt8](repeating: 0, count: self.count)
            self.copyBytes(to: &bytes, count: self.count * MemoryLayout<UInt32>.size)
            return NSUUID(uuidBytes: bytes)
        }
    }

    internal var stringASCII: String? {
        get {
            NSString(data: self, encoding: String.Encoding.ascii.rawValue) as String?
        }
    }

    internal var stringUTF8: String? {
        get {
            NSString(data: self, encoding: String.Encoding.utf8.rawValue) as String?
        }
    }

    internal init?(hexEncodedString: String) {
        let string = hexEncodedString.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(
            of: " ",
            with: ""
        )
        guard string.count.isMultiple(of: 2) else { return nil }
        let chars = string.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }
        guard string.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }

    internal var hexEncodedString: String {
        reduce("") { $0 + String(format: "%02x", $1) }
    }

    internal static func random(length: Int) -> Data {
        Data((0..<length).map { _ in UInt8.random(in: 0...UInt8.max) })
    }

    internal func padOrTrim(to length: Int) -> Data {
        if self.count == length {
            return self
        } else if self.count > length {
            return self.subdata(in: self.count - length..<self.count)
        } else {
            return Data(count: length - self.count) + self
        }
    }

    internal func xor(with key: Data) -> Data {
        guard self.count == key.count else { fatalError("XOR Data with different lengths is not supported") }
        var result = Data(count: self.count)
        for i in 0..<self.count {
            let byte = self.bytes[i] ^ key.bytes[i]
            result[i] = byte
        }
        return result
    }

    internal func shiftedLeftByOne() -> Data {
        var shifted = Data(count: bytes.count).bytes
        let last = self.count - 1
        for index in 0..<last {
            shifted[index] = self.bytes[index] << 1
            if (self.bytes[index + 1] & 0x80) != 0 {
                shifted[index] += 0x01
            }
        }
        shifted[last] = self.bytes[last] << 1
        return Data(shifted)
    }

    internal mutating func extract(_ count: Int) -> Data? {
        guard count > 0, count <= self.count else { return nil }
        let extractedData = self.prefix(count)
        self.removeFirst(count)
        return extractedData
    }

    internal mutating func secureClear() {
        self.resetBytes(in: 0..<self.count)
        self.removeAll()
    }
}

extension Int {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Int>.size)
    }
}

extension UInt8 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt8>.size)
    }

    internal var hexValue: String {
        String(format: "%02x", self)
    }
}

extension Int8 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Int8>.size)
    }
}

extension UInt16 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt16>.size)
    }
}

extension Int16 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Int16>.size)
    }
}

extension UInt32 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }

    internal var byteArrayLittleEndian: [UInt8] {
        [
            UInt8((self & 0xFF00_0000) >> 24),
            UInt8((self & 0x00FF_0000) >> 16),
            UInt8((self & 0x0000_FF00) >> 8),
            UInt8(self & 0x0000_00FF),
        ]
    }
}

extension UInt64 {
    internal var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt64>.size)
    }

    internal var byteArrayLittleEndian: [UInt8] {
        [
            UInt8((self & 0xFF00_0000_0000_0000) >> 56),
            UInt8((self & 0x00FF_0000_0000_0000) >> 48),
            UInt8((self & 0x0000_FF00_0000_0000) >> 40),
            UInt8((self & 0x0000_00FF_0000_0000) >> 32),
            UInt8((self & 0x0000_0000_FF00_0000) >> 24),
            UInt8((self & 0x0000_0000_00FF_0000) >> 16),
            UInt8((self & 0x0000_0000_0000_FF00) >> 8),
            UInt8(self & 0x0000_0000_0000_00FF),
        ]
    }
}
