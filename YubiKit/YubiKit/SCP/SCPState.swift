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

import CommonCrypto

struct SCPState: CustomDebugStringConvertible {
    var debugDescription: String {
        "SCPState(sessionKeys: \(sessionKeys), macChain: \(macChain.hexEncodedString), encCounter: \(encCounter)"
    }
    
    let sessionKeys: SCPSessionKeys
    var macChain: Data
    var encCounter: UInt32 = 1
    
    init(sessionKeys: SCPSessionKeys, macChain: Data) {
        self.sessionKeys = sessionKeys
        self.macChain = macChain
    }
    
    mutating func encrypt(_ data: Data) throws -> Data {
        print("👾 encrypt \(data.hexEncodedString) using \(self)")
        let paddedData = data.bitPadded()
        var ivData = Data(count: 12)
        ivData.append(self.encCounter.bigEndian.data)
        self.encCounter += 1
        let iv = try ivData.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES128), key: sessionKeys.senc)
        return try paddedData.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES128), key: sessionKeys.senc, iv: iv)
    }
    
    mutating func decrypt(_ data: Data) throws -> Data {
        print("decrypt: \(data.hexEncodedString)")
        var ivData = Data()
        ivData.append(UInt8(0x80))
        ivData.append(Data(count: 11))
        ivData.append((self.encCounter - 1).bigEndian.data)
        let iv = try ivData.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES128), key: sessionKeys.senc)
        var decrypted = try data.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES128), key: sessionKeys.senc, iv: iv)
        
        
        defer {
            decrypted.secureClear()
        }
        print("decrypted: \(decrypted.hexEncodedString)")
        return unpadData(decrypted)!
    }
    
    func unpadData(_ data: Data) -> Data? {
        guard let lastNonZeroIndex = data.lastIndex(where: { $0 != 0x00 }) else {
            return nil // The data is entirely zero or empty.
        }
        
        // Check if the last non-zero byte is 0x80
        if data[lastNonZeroIndex] == 0x80 {
            return data.prefix(upTo: lastNonZeroIndex) // Return data before padding
        }
        
        return nil // Invalid padding scheme
    }
    
    mutating func mac(data: Data) throws -> Data {
        let message = macChain + data
        self.macChain = try message.aescmac(key: sessionKeys.smac)
        return macChain.prefix(8)
    }
    
    mutating func unmac(data: Data, sw: UInt16) throws -> Data {
        let message = data.prefix(data.count - 8) + sw.bigEndian.data
        let rmac = try (macChain + message).aescmac(key: sessionKeys.srmac).prefix(8)
        guard rmac.constantTimeCompare(data.suffix(8)) else { throw "Tantrum" }
        return Data(message.prefix(message.count - 2))
    }
}
