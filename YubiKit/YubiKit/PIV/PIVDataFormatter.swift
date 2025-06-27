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
import CryptoKit
import Foundation

/// Utilities for formatting data for PIV cryptographic operations
internal enum PIVDataFormatter {

    /// Prepares data for RSA signing by applying the specified signature algorithm.
    ///
    /// This function creates a temporary RSA key pair to format the data according to the
    /// specified signature algorithm, then encrypts it with raw RSA encryption. This produces
    /// data in the format expected by the YubiKey's RSA signing operation.
    ///
    /// - Parameters:
    ///   - data: The data to be signed
    ///   - keySize: The RSA key size
    ///   - algorithm: The RSA signature algorithm to use
    /// - Returns: The prepared signature data
    /// - Throws: `PIV.SignatureError` if the operation fails
    internal static func prepareDataForRSASigning(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws -> Data {
        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keySize.inBits,
            ] as [CFString: Any]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let signedData = SecKeyCreateSignature(privateKey, algorithm.secKeyAlgorithm, data as CFData, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, signedData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return encryptedData as Data
    }

    /// Prepares data for ECDSA signing by hashing or formatting the input.
    ///
    /// For message signatures, this function hashes the input data using the specified
    /// hash algorithm. For digest signatures, it uses the data as-is (assuming it's
    /// already hashed). The resulting hash is then truncated or padded to match the
    /// key size as required by ECDSA.
    ///
    /// - Parameters:
    ///   - data: The data to be signed (raw message or pre-hashed digest)
    ///   - curve: The elliptic curve (P-256 or P-384)
    ///   - algorithm: The ECDSA signature algorithm to use
    /// - Returns: The prepared signature data (hash truncated/padded to key size)
    /// - Throws: `PIV.SignatureError` if the algorithm is unsupported
    internal static func prepareDataForECDSASigning(
        _ data: Data,
        curve: EC.Curve,
        algorithm: PIV.ECDSASignatureAlgorithm
    ) throws -> Data {
        var hash: Data
        switch algorithm {
        case .message(let hashAlg):
            switch hashAlg {
            case .sha1:
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
            case .sha224:
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
            case .sha256:
                hash = SHA256.hash(data: data).data
            case .sha384:
                hash = SHA384.hash(data: data).data
            case .sha512:
                hash = SHA512.hash(data: data).data
            }
        case .digest:
            // For digest signatures, the data is already hashed
            hash = data
        }

        let keySize = curve.keySizeInBits / 8
        if hash.count == keySize {
            return hash
        } else if hash.count > keySize {
            return hash.subdata(in: 0..<keySize)
        } else {
            return Data(count: keySize - hash.count) + hash
        }
    }

    /// Prepares data for RSA encryption by applying the specified encryption algorithm.
    ///
    /// This function creates a temporary RSA key pair to format the data according to the
    /// specified encryption algorithm. This produces data in the format expected by the
    /// YubiKey's RSA operation.
    ///
    /// - Parameters:
    ///   - data: The data to be encrypted
    ///   - keySize: The RSA key size
    ///   - algorithm: The RSA encryption algorithm to use
    /// - Returns: The prepared encryption data
    /// - Throws: `PIV.SignatureError` if the operation fails
    internal static func prepareDataForRSAEncryption(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws -> Data {
        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keySize.inBits,
            ] as [CFString: Any]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard
            let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm.secKeyAlgorithm, data as CFData, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        return encryptedData as Data
    }

    /// Extracts the original data from RSA encryption format.
    ///
    /// This function reverses the RSA encryption preparation by using a temporary RSA key pair
    /// to decrypt the encryption-formatted data.
    ///
    /// - Parameters:
    ///   - data: The RSA encryption-formatted data
    ///   - algorithm: The RSA encryption algorithm that was used
    /// - Returns: The extracted original data
    /// - Throws: `PIV.SignatureError` if the data size is invalid or decryption fails
    internal static func extractDataFromRSAEncryption(
        _ data: Data,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws -> Data {
        let validTypes: [PIV.RSAKey] = RSA.KeySize.allCases.compactMap { .rsa($0) }
        guard let keyType = validTypes.first(where: { $0.keysize.inBytes == data.count }) else {
            throw PIV.SignatureError.invalidDataSize
        }

        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keyType.keysize.inBits,
            ] as [CFString: Any]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard
            let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm.secKeyAlgorithm, encryptedData, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        return decryptedData as Data
    }

    /// Extracts the original data from RSA signature format.
    ///
    /// This function reverses the RSA signature preparation by using a temporary RSA key pair
    /// to decrypt the signature-formatted data.
    ///
    /// - Parameters:
    ///   - data: The RSA signature-formatted data
    ///   - algorithm: The RSA signature algorithm that was used
    /// - Returns: The extracted original data
    /// - Throws: `PIV.SignatureError` if the data size is invalid or decryption fails
    internal static func extractDataFromRSASigning(_ data: Data, algorithm: PIV.RSASignatureAlgorithm) throws -> Data {

        let validTypes: [PIV.RSAKey] = RSA.KeySize.allCases.compactMap { .rsa($0) }
        guard let keyType = validTypes.first(where: { $0.keysize.inBytes == data.count }) else {
            throw PIV.SignatureError.invalidDataSize
        }

        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keyType.keysize.inBits,
            ] as [CFString: Any]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard
            let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm.secKeyAlgorithm, encryptedData, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        return decryptedData as Data
    }
}
