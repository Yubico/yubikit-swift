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
import CryptoTokenKit

extension SecKey {
    
    internal static func secKey(fromYubiKeyData data: Data, type: PIVKeyType) throws -> SecKey {
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: data) else { throw PIVSessionError.dataParseError }
        switch type {
        case .ECCP256, .ECCP384:
            guard let eccKeyData = records.recordWithTag(0x86)?.value else { throw PIVSessionError.invalidResponse }
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                             kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(eccKeyData as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
            return publicKey
        case .RSA1024, .RSA2048, .RSA3072, .RSA4096:
            guard let modulus = records.recordWithTag(0x81)?.value,
                  let exponentData = records.recordWithTag(0x82)?.value
            else { throw PIVSessionError.invalidResponse }
            let modulusData = UInt8(0x00).data + modulus
            var data = Data()
            data.append(TKBERTLVRecord(tag: 0x02, value: modulusData).data)
            data.append(TKBERTLVRecord(tag: 0x02, value: exponentData).data)
            let keyRecord = TKBERTLVRecord(tag: 0x30, value: data)
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                             kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(keyRecord.data as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
            return publicKey
        case .unknown:
            throw PIVSessionError.unknownKeyType
        }
    }
    
    var type: PIVKeyType? {
        guard let attributes = SecKeyCopyAttributes(self) as? Dictionary<String, Any>,
              let size = attributes[kSecAttrKeySizeInBits as String] as? UInt,
              let type = attributes[kSecAttrKeyType as String] as? String else { return nil }
        if type == kSecAttrKeyTypeRSA as String {
            if size == 1024 {
                return .RSA1024
            }
            if size == 2048 {
                return .RSA2048
            }
        }
        if type == kSecAttrKeyTypeEC as String {
            if size == 256 {
                return .ECCP256
            }
            if size == 384 {
                return .ECCP384
            }
        }
        return nil
    }
    
}
