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
import CryptoKit

public enum PIVPaddingError: Error {
    case unsupportedAlgorithm, unknownKeyType, unknownPaddingError, wrongInputBufferSize
}

public enum PIVPadding {
    
    public static func pad(data: Data, keyType: PIVKeyType, algorithm: SecKeyAlgorithm) throws -> Data {
        if keyType == .RSA1024 || keyType == .RSA2048 {
            let keySize = keyType.size * 8
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                        kSecAttrKeySizeInBits: keySize] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey)
            else {
                throw error!.takeRetainedValue() as Error
            }
            guard let signedData = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
                throw error!.takeRetainedValue() as Error

            }
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, signedData, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return encryptedData as Data
        } else if keyType == .ECCP256 || keyType == .ECCP384 {
            var hash: Data
            switch algorithm {
            case SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1:
                hash = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
                hash.withUnsafeMutableBytes { (hashPtr) in
                    if let rawHashPtr = hashPtr.baseAddress {
                        data.withUnsafeBytes { (dataPtr) in
                            if let rawDataPtr = dataPtr.baseAddress {
                                let _ = CC_SHA1(rawDataPtr, CC_LONG(data.count), rawHashPtr)
                            }
                        }
                    }
                }           
            case SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224:
                hash = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
                hash.withUnsafeMutableBytes { (hashPtr) in
                    if let rawHashPtr = hashPtr.baseAddress {
                        data.withUnsafeBytes { (dataPtr) in
                            if let rawDataPtr = dataPtr.baseAddress {
                                let _ = CC_SHA224(rawDataPtr, CC_LONG(data.count), rawHashPtr)
                            }
                        }
                    }
                }
            case SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256:
                hash = SHA256.hash(data: data).data
            case SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384:
                hash = SHA384.hash(data: data).data
            case SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512:
                hash = SHA512.hash(data: data).data
            case SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1,
                SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224,
                SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256,
                SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384,
                SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512:
                hash = data
            default:
                throw PIVPaddingError.unsupportedAlgorithm
            }
            let keySize = Int(keyType.size)
            if hash.count == keySize {
                return hash
            } else if hash.count > keySize {
                return hash.subdata(in: 0..<keySize)
            } else if hash.count < keySize {
                return Data(count: keySize - hash.count) + hash
            }
        } else {
            throw PIVPaddingError.unknownKeyType
        }
        throw PIVPaddingError.unknownPaddingError
    }
    
    public static func unpadRSAData(_ data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
        let size: UInt
        switch data.count {
        case 1024 / 8:
            size = 1024
        case 2048 / 8:
            size = 2048
        default:
            throw PIVPaddingError.wrongInputBufferSize
        }
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecAttrKeySizeInBits: size] as [CFString : Any]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, encryptedData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return decryptedData as Data
    }
}
