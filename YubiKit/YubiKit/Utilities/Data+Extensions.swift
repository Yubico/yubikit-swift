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
import CommonCrypto

enum PIVEncryptionError: Error {
    case cryptorError(CCCryptorStatus)
    case missingData
    case unsupportedAlgorithm
}

extension Data {
    
    public func encrypt(algorithm: CCAlgorithm, key: Data) throws -> Data {
        try cryptOperation(UInt32(kCCEncrypt), algorithm: algorithm, key: key)
    }
    
    public func decrypt(algorithm: CCAlgorithm, key: Data) throws -> Data {
        try cryptOperation(UInt32(kCCDecrypt), algorithm: algorithm, key: key)
    }
    
    private func cryptOperation(_ operation: CCOperation, algorithm: CCAlgorithm, key: Data) throws -> Data {
        guard !key.isEmpty else { throw PIVEncryptionError.missingData }
        
        let blockSize: Int
        switch Int(algorithm) {
        case kCCAlgorithm3DES:
            blockSize = kCCBlockSize3DES
        case kCCAlgorithmAES:
            blockSize = kCCBlockSizeAES128
        default:
            throw PIVEncryptionError.unsupportedAlgorithm
        }
        
        var outLength: Int = 0
        let bufferLength = self.count + blockSize
        var buffer = Data(count: bufferLength)

        let cryptorStatus: CCCryptorStatus = buffer.withUnsafeMutableBytes { buffer in
            self.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    var ccRef: CCCryptorRef?
                    CCCryptorCreate(operation, algorithm, CCOptions(kCCOptionECBMode), keyBytes.baseAddress, key.count, nil, &ccRef)
                    return CCCryptorUpdate(ccRef, dataBytes.baseAddress, self.count, buffer.baseAddress, bufferLength, &outLength)
                }
            }
        }
        
        guard cryptorStatus == kCCSuccess else { throw PIVEncryptionError.cryptorError(cryptorStatus) }
        return buffer.subdata(in: 0..<outLength)
    }
    
    var bytes: [UInt8] {
        [UInt8](self)
    }
    
    var uint8: UInt8 {
        get {
            var number: UInt8 = 0
            self.copyBytes(to:&number, count: MemoryLayout<UInt8>.size)
            return number
        }
    }
    
    var uint16: UInt16 {
        get {
            let i16array = self.withUnsafeBytes { $0.load(as: UInt16.self) }
            return i16array
        }
    }
    
    var uint32: UInt32 {
        get {
            let i32array = self.withUnsafeBytes { $0.load(as: UInt32.self) }
            return i32array
        }
    }
    
    var uuid: NSUUID? {
        get {
            var bytes = [UInt8](repeating: 0, count: self.count)
            self.copyBytes(to:&bytes, count: self.count * MemoryLayout<UInt32>.size)
            return NSUUID(uuidBytes: bytes)
        }
    }
    
    var stringASCII: String? {
        get {
            return NSString(data: self, encoding: String.Encoding.ascii.rawValue) as String?
        }
    }
    
    var stringUTF8: String? {
        get {
            return NSString(data: self, encoding: String.Encoding.utf8.rawValue) as String?
        }
    }
    
    public init?(hexEncodedString: String) {
        let string = hexEncodedString.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: " ", with: "")
        guard string.count.isMultiple(of: 2) else { return nil }
        let chars = string.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }
        guard string.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }
    
    public var hexEncodedString: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
    
    static func random(length: Int) -> Data {
        return Data((0..<length).map { _ in UInt8.random(in: 0...UInt8.max) })
    }
    
    func padOrTrim(to length: Int) -> Data {
        if self.count == length {
            return self
        } else if self.count > length {
            return self.subdata(in: self.count - length ..< self.count)
        } else {
            return Data(count: length - self.count) + self
        }
    }
}


extension Int {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Int>.size)
    }
}

extension UInt8 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt8>.size)
    }
    
    var hexValue: String {
        return String(format: "%02x", self)
    }
}

extension UInt16 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt16>.size)
    }
}

extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
    
    var byteArrayLittleEndian: [UInt8] {
        return [
            UInt8((self & 0xFF000000) >> 24),
            UInt8((self & 0x00FF0000) >> 16),
            UInt8((self & 0x0000FF00) >> 8),
            UInt8(self &  0x000000FF)
        ]
    }
}

extension UInt64 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt64>.size)
    }
    
    var byteArrayLittleEndian: [UInt8] {
        return [
            UInt8((self & 0xFF00000000000000) >> 56),
            UInt8((self & 0x00FF000000000000) >> 48),
            UInt8((self & 0x0000FF0000000000) >> 40),
            UInt8((self & 0x000000FF00000000) >> 32),
            UInt8((self & 0x00000000FF000000) >> 24),
            UInt8((self & 0x0000000000FF0000) >> 16),
            UInt8((self & 0x000000000000FF00) >> 8),
            UInt8(self &  0x00000000000000FF)
        ]
    }
}
