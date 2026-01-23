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
import Security

// MARK: - Crypto.RSA

extension Crypto.RSA {

    /// Generates a random RSA private key and returns its PKCS#1 DER encoding.
    /// - Parameter bitCount: The key size in bits (e.g., 1024, 2048).
    /// - Returns: The PKCS#1 DER-encoded private key data.
    /// - Throws: `CryptoError.keyCreationFailed` if generation fails.
    static func generateRandomPrivateKey(bitCount: Int) throws(CryptoError) -> Data {
        let (privateKey, _) = try SecKeyHelpers.generateRSAKeyPair(bitCount: bitCount)
        return try SecKeyHelpers.exportSecKey(privateKey)
    }

    /// Prepares data for RSA signing by applying the specified signature algorithm padding.
    static func prepareSignatureData(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(CryptoError) -> Data {
        try SecKeyHelpers.prepareRSASignatureData(
            data,
            bitCount: keySize.bitCount,
            algorithm: algorithm.secKeyAlgorithm
        )
    }

    /// Prepares data for RSA encryption by applying the specified encryption algorithm padding.
    static func prepareEncryptionData(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(CryptoError) -> Data {
        try SecKeyHelpers.prepareRSAEncryptionData(
            data,
            bitCount: keySize.bitCount,
            algorithm: algorithm.secKeyAlgorithm
        )
    }

    /// Extracts original data from RSA encryption format by removing padding.
    static func extractEncryptionData(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(CryptoError) -> Data {
        try SecKeyHelpers.extractRSAEncryptionData(
            data,
            bitCount: keySize.bitCount,
            algorithm: algorithm.secKeyAlgorithm
        )
    }

    /// Extracts original data from RSA signature format by removing padding.
    static func extractSignatureData(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(CryptoError) -> Data {
        try SecKeyHelpers.extractRSASignatureData(
            data,
            bitCount: keySize.bitCount,
            algorithm: algorithm.secKeyAlgorithm
        )
    }
}

// MARK: - Crypto.EC

extension Crypto.EC {

    /// Generates a random EC private key and returns its uncompressed representation.
    /// - Parameter curve: The elliptic curve to use.
    /// - Returns: The uncompressed private key data.
    /// - Throws: `CryptoError.keyCreationFailed` if generation fails.
    static func generateRandomPrivateKey(curve: EC.Curve) throws(CryptoError) -> Data {
        // Determine key type (when adding new curves, ensure the correct Security framework key type is used)
        let keyType: CFString
        switch curve {
        case .secp256r1, .secp384r1:
            keyType = kSecAttrKeyTypeECSECPrimeRandom
        }

        // Generate key pair
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: keyType,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }

        // Export private key
        guard let data = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }
        return data
    }

    /// Performs ECDH key agreement using EC key types.
    /// - Parameters:
    ///   - privateKey: The EC private key.
    ///   - publicKey: The peer's EC public key (must be on the same curve as privateKey).
    /// - Returns: The shared secret.
    /// - Throws: `CryptoError.keyAgreementFailed` or `CryptoError.keyCreationFailed`.
    static func sharedSecret(privateKey: EC.PrivateKey, publicKey: EC.PublicKey) throws(CryptoError) -> Data {
        guard privateKey.curve == publicKey.curve else {
            throw .keyAgreementFailed
        }
        let curve = privateKey.curve

        // Determine key type (when adding new curves, ensure the correct Security framework key type is used)
        let keyType: CFString
        switch curve {
        case .secp256r1, .secp384r1:
            keyType = kSecAttrKeyTypeECSECPrimeRandom
        }

        // Create SecKey from private key data
        let privateKeyAttributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: keyType,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]
        var error: Unmanaged<CFError>?
        guard
            let privateSecKey = SecKeyCreateWithData(
                privateKey.uncompressedRepresentation as CFData,
                privateKeyAttributes as CFDictionary,
                &error
            )
        else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }

        // Create SecKey from public key data
        let publicKeyAttributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: keyType,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]
        guard
            let publicSecKey = SecKeyCreateWithData(
                publicKey.uncompressedPoint as CFData,
                publicKeyAttributes as CFDictionary,
                &error
            )
        else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }

        // Perform ECDH key exchange
        let params: [String: Any] = [:]
        guard
            let secretData = SecKeyCopyKeyExchangeResult(
                privateSecKey,
                .ecdhKeyExchangeStandard,
                publicSecKey,
                params as CFDictionary,
                &error
            )
        else {
            throw .keyAgreementFailed
        }
        return secretData as Data
    }
}

// MARK: - Crypto.X509

extension Crypto.X509 {

    /// Extracts a PublicKey from X.509 DER-encoded certificate data.
    /// - Parameter der: The DER-encoded certificate data.
    /// - Returns: The extracted PublicKey, or nil if extraction fails.
    static func extractPublicKey(fromDER der: Data) -> PublicKey? {
        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
            return nil
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(cert, policy, &trust)
        guard status == errSecSuccess, let trust = trust else {
            return nil
        }

        guard let secKey = SecTrustCopyKey(trust) else {
            return nil
        }

        return SecKeyHelpers.publicKey(from: secKey)
    }
}

// MARK: - PIV Algorithm Mapping (Fileprivate)

extension PIV.RSASignatureAlgorithm {
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

// MARK: - SecKey Helpers (Private)

/// Private helpers for SecKey operations. Not exposed outside the Crypto module.
private enum SecKeyHelpers {

    // MARK: - Key Generation

    static func generateRSAKeyPair(bitCount: Int) throws(CryptoError) -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: bitCount,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }

        return (privateKey, publicKey)
    }

    // MARK: - SecKey Export

    static func exportSecKey(_ key: SecKey) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }
        return data
    }

    // MARK: - SecKey Attributes

    struct KeyAttributes {
        let keyClass: CFString
        let keyType: CFString
        let keySizeInBits: Int
    }

    static func getAttributes(of key: SecKey) -> KeyAttributes? {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
            let keySizeInBits = attributes[kSecAttrKeySizeInBits] as? Int,
            let keyClass = attributes[kSecAttrKeyClass] as? String,
            let keyType = attributes[kSecAttrKeyType] as? String
        else {
            return nil
        }

        return KeyAttributes(keyClass: keyClass as CFString, keyType: keyType as CFString, keySizeInBits: keySizeInBits)
    }

    static func isPublicKey(_ key: SecKey) -> Bool {
        guard let attributes = getAttributes(of: key) else { return false }
        return attributes.keyClass == kSecAttrKeyClassPublic
    }

    static func isRSAKey(_ key: SecKey) -> Bool {
        guard let attributes = getAttributes(of: key) else { return false }
        return attributes.keyType == kSecAttrKeyTypeRSA
    }

    static func isECKey(_ key: SecKey) -> Bool {
        guard let attributes = getAttributes(of: key) else { return false }
        return attributes.keyType == kSecAttrKeyTypeECSECPrimeRandom
    }

    // MARK: - RSA Operations

    static func rsaSign(_ data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            throw .signingFailed(error?.takeRetainedValue())
        }
        return signature as Data
    }

    static func rsaEncrypt(_ data: Data, publicKey: SecKey, algorithm: SecKeyAlgorithm) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            throw .encryptionFailed(error?.takeRetainedValue())
        }
        return encrypted as Data
    }

    static func rsaDecrypt(_ data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(privateKey, algorithm, data as CFData, &error) else {
            throw .decryptionFailed(error?.takeRetainedValue())
        }
        return decrypted as Data
    }

    // MARK: - Public Key Conversion

    static func publicKey(from secKey: SecKey) -> PublicKey? {
        guard isPublicKey(secKey) else {
            return nil
        }

        guard let attributes = getAttributes(of: secKey) else {
            return nil
        }

        guard let blob = try? exportSecKey(secKey) else {
            return nil
        }

        if isRSAKey(secKey) {
            let key = RSA.PublicKey(pkcs1: blob)
            guard let keySize = RSA.KeySize(rawValue: attributes.keySizeInBits),
                keySize == key?.size
            else {
                return nil
            }
            return key.map { .rsa($0) }

        } else if isECKey(secKey) {
            return [EC.Curve.secp256r1, EC.Curve.secp384r1]
                .compactMap { EC.PublicKey(uncompressedPoint: blob, curve: $0) }
                .map { PublicKey.ec($0) }
                .first

        } else {
            // Curve25519 keys
            if let key = Ed25519.PublicKey(keyData: blob) {
                return .ed25519(key)
            } else if let key = X25519.PublicKey(keyData: blob) {
                return .x25519(key)
            }
            return nil
        }
    }

    // MARK: - RSA Data Formatting

    static func prepareRSASignatureData(
        _ data: Data,
        bitCount: Int,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        let (privateKey, publicKey) = try generateRSAKeyPair(bitCount: bitCount)
        let signedData = try rsaSign(data, privateKey: privateKey, algorithm: algorithm)
        return try rsaEncrypt(signedData, publicKey: publicKey, algorithm: .rsaEncryptionRaw)
    }

    static func prepareRSAEncryptionData(
        _ data: Data,
        bitCount: Int,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        let (_, publicKey) = try generateRSAKeyPair(bitCount: bitCount)
        return try rsaEncrypt(data, publicKey: publicKey, algorithm: algorithm)
    }

    static func extractRSAEncryptionData(
        _ data: Data,
        bitCount: Int,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        let (privateKey, publicKey) = try generateRSAKeyPair(bitCount: bitCount)
        let encryptedData = try rsaEncrypt(data, publicKey: publicKey, algorithm: .rsaEncryptionRaw)
        return try rsaDecrypt(encryptedData, privateKey: privateKey, algorithm: algorithm)
    }

    static func extractRSASignatureData(
        _ data: Data,
        bitCount: Int,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        let (privateKey, publicKey) = try generateRSAKeyPair(bitCount: bitCount)
        let encryptedData = try rsaEncrypt(data, publicKey: publicKey, algorithm: .rsaEncryptionRaw)
        return try rsaDecrypt(encryptedData, privateKey: privateKey, algorithm: algorithm)
    }
}
