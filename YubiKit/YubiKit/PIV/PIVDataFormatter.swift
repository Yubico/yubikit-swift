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

// Utilities for formatting data for PIV cryptographic operations
internal enum PIVDataFormatter {

    // Prepares data for RSA signing by applying the specified signature algorithm.
    // Creates a temporary RSA key pair to format the data according to the
    // specified signature algorithm, then encrypts it with raw RSA encryption.
    internal static func prepareDataForRSASigning(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(PIVSessionError) -> Data {
        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keySize.bitCount,
            ] as [CFString: Any]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw .cryptoError(
                "Failed to create RSA key pair for signing",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard let signedData = SecKeyCreateSignature(privateKey, algorithm.secKeyAlgorithm, data as CFData, &error)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, signedData, &error) else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        return encryptedData as Data
    }

    // Prepares data for ECDSA signing by hashing or formatting the input.
    // For message signatures, hashes the input data. For digest signatures, uses data as-is.
    // The resulting hash is truncated or padded to match the key size.
    internal static func prepareDataForECDSASigning(
        _ data: Data,
        curve: EC.Curve,
        algorithm: PIV.ECDSASignatureAlgorithm
    ) -> Data {
        var hash: Data
        switch algorithm {
        case .hash(let hashAlg):
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
        case .prehashed:
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

    // Prepares data for RSA encryption by applying the specified encryption algorithm.
    // Creates a temporary RSA key pair to format the data according to the
    // specified encryption algorithm.
    internal static func prepareDataForRSAEncryption(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(PIVSessionError) -> Data {
        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keySize.bitCount,
            ] as [CFString: Any]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard
            let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm.secKeyAlgorithm, data as CFData, &error)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        return encryptedData as Data
    }

    // Extracts the original data from RSA encryption format.
    // Reverses the RSA encryption preparation by using a temporary RSA key pair
    // to decrypt the encryption-formatted data.
    internal static func extractDataFromRSAEncryption(
        _ data: Data,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(PIVSessionError) -> Data {
        let validTypes: [PIV.RSAKey] = RSA.KeySize.allCases.compactMap { .rsa($0) }
        guard let keyType = validTypes.first(where: { $0.keysize.byteCount == data.count }) else {
            throw .invalidDataSize(source: .here())
        }

        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keyType.keysize.bitCount,
            ] as [CFString: Any]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard
            let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm.secKeyAlgorithm, encryptedData, &error)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        return decryptedData as Data
    }

    // Extracts the original data from RSA signature format.
    // Reverses the RSA signature preparation by using a temporary RSA key pair
    // to decrypt the signature-formatted data.
    internal static func extractDataFromRSASigning(
        _ data: Data,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(PIVSessionError) -> Data {

        let validTypes: [PIV.RSAKey] = RSA.KeySize.allCases.compactMap { .rsa($0) }
        guard let keyType = validTypes.first(where: { $0.keysize.byteCount == data.count }) else {
            throw .invalidDataSize(source: .here())
        }

        let attributes =
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: keyType.keysize.bitCount,
            ] as [CFString: Any]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        guard
            let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm.secKeyAlgorithm, encryptedData, &error)
        else {
            throw .cryptoError(
                "Failed to perform RSA cryptographic operation",
                error: error?.takeRetainedValue(),
                source: .here()
            )
        }
        return decryptedData as Data
    }
}

extension PIV.RSASignatureAlgorithm {
    // Maps to the corresponding SecKeyAlgorithm
    fileprivate var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .pkcs1v15(let hash):
            switch hash {
            case .sha1: return .rsaSignatureMessagePKCS1v15SHA1
            case .sha224: return .rsaSignatureMessagePKCS1v15SHA224
            case .sha256: return .rsaSignatureMessagePKCS1v15SHA256
            case .sha384: return .rsaSignatureMessagePKCS1v15SHA384
            case .sha512: return .rsaSignatureMessagePKCS1v15SHA512
            }
        case .pss(let hash):
            switch hash {
            case .sha1: return .rsaSignatureMessagePSSSHA1
            case .sha224: return .rsaSignatureMessagePSSSHA224
            case .sha256: return .rsaSignatureMessagePSSSHA256
            case .sha384: return .rsaSignatureMessagePSSSHA384
            case .sha512: return .rsaSignatureMessagePSSSHA512
            }
        case .raw:
            return .rsaSignatureRaw
        }
    }
}

extension PIV.RSAEncryptionAlgorithm {
    // Maps to the corresponding SecKeyAlgorithm
    fileprivate var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .pkcs1v15:
            return .rsaEncryptionPKCS1
        case .oaep(let hash):
            switch hash {
            case .sha1: return .rsaEncryptionOAEPSHA1
            case .sha224: return .rsaEncryptionOAEPSHA224
            case .sha256: return .rsaEncryptionOAEPSHA256
            case .sha384: return .rsaEncryptionOAEPSHA384
            case .sha512: return .rsaEncryptionOAEPSHA512
            }
        case .raw:
            return .rsaEncryptionRaw
        }
    }
}
