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
import Security

/// Namespace for cryptographic operations.
internal enum Crypto {

    // MARK: - Nested Namespaces

    /// Cryptographic hash functions.
    enum Hash {}

    /// HMAC (Hash-based Message Authentication Code) functions.
    enum HMAC {}

    /// AES symmetric encryption operations.
    enum AES {}

    /// Triple DES symmetric encryption operations.
    enum TripleDES {}

    /// RSA asymmetric cryptography operations.
    enum RSA {}

    /// Elliptic curve cryptography operations.
    enum EC {}

    /// P-256 elliptic curve key agreement operations.
    enum P256 {}

    /// Curve25519 key validation and derivation operations.
    enum Curve25519 {}

    /// X.509 certificate operations.
    enum X509 {}

    /// Key derivation functions.
    enum KDF {}

    /// Cryptographically secure random number generation.
    enum Random {}

    // MARK: - Constants

    /// AES block size in bytes.
    static let aesBlockSize = kCCBlockSizeAES128

    /// SHA-1 block size in bytes.
    static let sha1BlockSize = Int(CC_SHA1_BLOCK_BYTES)

    /// SHA-256 block size in bytes.
    static let sha256BlockSize = Int(CC_SHA256_BLOCK_BYTES)

    /// SHA-512 block size in bytes.
    static let sha512BlockSize = Int(CC_SHA512_BLOCK_BYTES)

    // MARK: - Utilities

    /// Compares two Data values in constant time to prevent timing attacks.
    static func constantTimeCompare(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    // MARK: - Private Helpers (used by nested enums in this file)

    /// Performs symmetric encryption/decryption operation.
    fileprivate static func cryptOperation(
        _ operation: Int,
        data: Data,
        algorithm: CCAlgorithm,
        mode: CCMode,
        key: Data,
        iv: Data?
    ) throws(CryptoError) -> Data {
        guard !key.isEmpty else { throw CryptoError.missingData }

        let blockSize: Int
        switch Int(algorithm) {
        case kCCAlgorithm3DES:
            blockSize = kCCBlockSize3DES
        case kCCAlgorithmAES, kCCAlgorithmAES128:
            blockSize = kCCBlockSizeAES128
        default:
            throw CryptoError.unsupportedAlgorithm
        }

        var outLength: Int = 0
        let bufferLength = data.count + blockSize
        var buffer = Data(count: bufferLength)
        let iv = iv ?? Data()

        let cryptorStatus: CCCryptorStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        var cryptorRef: CCCryptorRef?
                        let createStatus = CCCryptorCreateWithMode(
                            CCOperation(operation),
                            mode,
                            algorithm,
                            CCPadding(ccNoPadding),
                            iv.count > 0 ? ivBytes.baseAddress : nil,
                            keyBytes.baseAddress,
                            key.count,
                            nil,
                            0,
                            0,
                            0,
                            &cryptorRef
                        )
                        guard createStatus == kCCSuccess, let cryptor = cryptorRef else {
                            return createStatus
                        }
                        defer { CCCryptorRelease(cryptor) }
                        return CCCryptorUpdate(
                            cryptor,
                            dataBytes.baseAddress,
                            data.count,
                            bufferBytes.baseAddress,
                            bufferLength,
                            &outLength
                        )
                    }
                }
            }
        }

        guard cryptorStatus == kCCSuccess else { throw CryptoError.cryptorError(cryptorStatus) }
        return buffer.subdata(in: 0..<outLength)
    }
}

// MARK: - Crypto.Hash

extension Crypto.Hash {
    /// Computes SHA-1 hash.
    /// - Note: SHA-1 is cryptographically weak and should only be used for legacy compatibility.
    static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    /// Computes SHA-224 hash.
    /// - Note: CryptoKit doesn't include SHA-224, so we use CommonCrypto.
    static func sha224(_ data: Data) -> Data {
        var hash = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
        hash.withUnsafeMutableBytes { hashPtr in
            guard let hashBase = hashPtr.bindMemory(to: UInt8.self).baseAddress else { return }
            data.withUnsafeBytes { dataPtr in
                _ = CC_SHA224(dataPtr.baseAddress, CC_LONG(data.count), hashBase)
            }
        }
        return hash
    }

    /// Computes SHA-256 hash.
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// Computes SHA-384 hash.
    static func sha384(_ data: Data) -> Data {
        Data(SHA384.hash(data: data))
    }

    /// Computes SHA-512 hash.
    static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }
}

// MARK: - Crypto.HMAC

extension Crypto.HMAC {
    /// Computes HMAC-SHA1.
    /// - Note: HMAC-SHA1 is used for legacy compatibility (e.g., OATH TOTP/HOTP).
    static func sha1(_ data: Data, key: Data) -> Data {
        let hmac = CryptoKit.HMAC<Insecure.SHA1>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }

    /// Computes HMAC-SHA256.
    static func sha256(_ data: Data, key: Data) -> Data {
        let hmac = CryptoKit.HMAC<SHA256>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }
}

// MARK: - Crypto.AES

extension Crypto.AES {
    /// Block size in bytes.
    static let blockSize = kCCBlockSizeAES128

    /// Encrypts data using AES.
    /// - Parameters:
    ///   - data: Data to encrypt (must be block-aligned).
    ///   - key: AES key (16, 24, or 32 bytes).
    ///   - iv: Initialization vector for CBC mode. If nil, uses ECB mode.
    /// - Returns: Encrypted data.
    static func encrypt(_ data: Data, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try Crypto.cryptOperation(kCCEncrypt, data: data, algorithm: CCAlgorithm(kCCAlgorithmAES), mode: mode, key: key, iv: iv)
    }

    /// Decrypts data using AES.
    /// - Parameters:
    ///   - data: Data to decrypt.
    ///   - key: AES key (16, 24, or 32 bytes).
    ///   - iv: Initialization vector for CBC mode. If nil, uses ECB mode.
    /// - Returns: Decrypted data.
    static func decrypt(_ data: Data, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try Crypto.cryptOperation(kCCDecrypt, data: data, algorithm: CCAlgorithm(kCCAlgorithmAES), mode: mode, key: key, iv: iv)
    }

    /// Computes AES-CMAC.
    static func cmac(_ data: Data, key: Data) throws(CryptoError) -> Data {
        let blockSize = kCCBlockSizeAES128
        let constZero = Data(count: blockSize)
        let constRb = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
        ])
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)

        let l = try Crypto.cryptOperation(kCCEncrypt, data: constZero, algorithm: algorithm, mode: CCMode(kCCModeCBC), key: key, iv: constZero)
        var subKey1 = l.shiftedLeftByOne()
        if (l[0] & 0x80) != 0 {
            subKey1 = constRb.xor(with: subKey1)
        }
        var subKey2 = subKey1.shiftedLeftByOne()
        if (subKey1[0] & 0x80) != 0 {
            subKey2 = constRb.xor(with: subKey2)
        }

        let lastBlockIsComplete = data.count % blockSize == 0 && data.count > 0

        let paddedData: Data
        var lastIv: Data
        if lastBlockIsComplete {
            lastIv = subKey1
            paddedData = data
        } else {
            lastIv = subKey2
            paddedData = bitPadded(data)
        }
        let messageSkippingLastBlock = paddedData.subdata(in: 0..<(paddedData.count - blockSize))
        let lastBlock = paddedData.subdata(in: messageSkippingLastBlock.count..<paddedData.count)

        if messageSkippingLastBlock.count != 0 {
            let encryptedBlock = try Crypto.cryptOperation(
                kCCEncrypt,
                data: messageSkippingLastBlock,
                algorithm: algorithm,
                mode: CCMode(kCCModeCBC),
                key: key,
                iv: constZero
            ).subdata(in: (messageSkippingLastBlock.count - blockSize)..<messageSkippingLastBlock.count)
            lastIv = lastIv.xor(with: encryptedBlock)
        }

        return try Crypto.cryptOperation(kCCEncrypt, data: lastBlock, algorithm: algorithm, mode: CCMode(kCCModeCBC), key: key, iv: lastIv)
    }

    /// Applies bit padding for CMAC.
    static func bitPadded(_ data: Data) -> Data {
        let blockSize = kCCBlockSizeAES128
        var paddedData = data
        paddedData.append(0x80)
        let remainder = data.count % blockSize
        let zeroPadding = remainder == 0 ? blockSize - 1 : blockSize - 1 - remainder
        return paddedData + Data(count: zeroPadding)
    }

    /// AES-GCM authenticated encryption operations.
    enum GCM {
        /// Standard nonce size for AES-GCM (12 bytes).
        static let nonceSize = 12
        /// Authentication tag size (16 bytes).
        static let tagSize = 16

        /// Sealed box containing ciphertext and authentication tag.
        struct SealedBox: Sendable, Equatable {
            /// The ciphertext (excluding nonce).
            let ciphertext: Data
            /// The authentication tag.
            let tag: Data

            /// Combined ciphertext and tag (ciphertext || tag).
            var ciphertextAndTag: Data {
                ciphertext + tag
            }

            init(ciphertext: Data, tag: Data) {
                self.ciphertext = ciphertext
                self.tag = tag
            }

            /// Initialize from combined ciphertext and tag.
            init?(combined: Data) {
                guard combined.count >= tagSize else { return nil }
                self.ciphertext = combined.dropLast(tagSize)
                self.tag = combined.suffix(tagSize)
            }
        }

        /// Encrypts and authenticates data using AES-GCM.
        /// - Parameters:
        ///   - data: The plaintext to encrypt.
        ///   - key: The 128, 192, or 256-bit AES key.
        ///   - nonce: The 12-byte nonce (IV).
        ///   - authenticating: Additional authenticated data (AAD).
        /// - Returns: A sealed box containing ciphertext and authentication tag.
        static func seal(
            _ data: Data,
            key: Data,
            nonce: Data,
            authenticating aad: Data = Data()
        ) throws(CryptoError) -> SealedBox {
            guard nonce.count == nonceSize else {
                throw .missingData
            }
            do {
                let symmetricKey = SymmetricKey(data: key)
                let gcmNonce = try CryptoKit.AES.GCM.Nonce(data: nonce)
                let sealedBox = try CryptoKit.AES.GCM.seal(data, using: symmetricKey, nonce: gcmNonce, authenticating: aad)
                // sealedBox.combined is nonce + ciphertext + tag
                guard let combined = sealedBox.combined else {
                    throw CryptoError.encryptionFailed(nil)
                }
                // Remove the nonce prefix to get ciphertext + tag
                let ciphertextAndTag = combined.dropFirst(nonceSize)
                return SealedBox(combined: Data(ciphertextAndTag))!
            } catch let error as CryptoError {
                throw error
            } catch {
                throw .encryptionFailed(error)
            }
        }

        /// Decrypts and verifies data using AES-GCM.
        /// - Parameters:
        ///   - sealedBox: The sealed box containing ciphertext and tag.
        ///   - key: The 128, 192, or 256-bit AES key.
        ///   - nonce: The 12-byte nonce (IV) used during encryption.
        ///   - authenticating: Additional authenticated data (AAD).
        /// - Returns: The decrypted plaintext.
        static func open(
            _ sealedBox: SealedBox,
            key: Data,
            nonce: Data,
            authenticating aad: Data = Data()
        ) throws(CryptoError) -> Data {
            guard nonce.count == nonceSize else {
                throw .missingData
            }
            do {
                let symmetricKey = SymmetricKey(data: key)
                // Reconstruct the combined format: nonce + ciphertext + tag
                let combined = nonce + sealedBox.ciphertextAndTag
                let gcmSealedBox = try CryptoKit.AES.GCM.SealedBox(combined: combined)
                return try CryptoKit.AES.GCM.open(gcmSealedBox, using: symmetricKey, authenticating: aad)
            } catch let error as CryptoError {
                throw error
            } catch {
                throw .decryptionFailed(error)
            }
        }
    }
}

// MARK: - Crypto.TripleDES

extension Crypto.TripleDES {
    /// Encrypts data using Triple DES.
    /// - Parameters:
    ///   - data: Data to encrypt (must be block-aligned).
    ///   - key: 3DES key (24 bytes).
    ///   - iv: Initialization vector for CBC mode. If nil, uses ECB mode.
    /// - Returns: Encrypted data.
    static func encrypt(_ data: Data, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try Crypto.cryptOperation(kCCEncrypt, data: data, algorithm: CCAlgorithm(kCCAlgorithm3DES), mode: mode, key: key, iv: iv)
    }

    /// Decrypts data using Triple DES.
    /// - Parameters:
    ///   - data: Data to decrypt.
    ///   - key: 3DES key (24 bytes).
    ///   - iv: Initialization vector for CBC mode. If nil, uses ECB mode.
    /// - Returns: Decrypted data.
    static func decrypt(_ data: Data, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try Crypto.cryptOperation(kCCDecrypt, data: data, algorithm: CCAlgorithm(kCCAlgorithm3DES), mode: mode, key: key, iv: iv)
    }
}

// MARK: - Crypto.KDF

extension Crypto.KDF {
    /// Derives a key using HKDF-SHA256.
    static func hkdf(_ data: Data, salt: Data, info: String, outputLength: Int) -> Data {
        hkdf(data, salt: salt, info: Data(info.utf8), outputLength: outputLength)
    }

    /// Derives a key using HKDF-SHA256.
    static func hkdf(_ data: Data, salt: Data, info: Data, outputLength: Int) -> Data {
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: data),
            salt: salt,
            info: info,
            outputByteCount: outputLength
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }

    /// Derives a key using PBKDF2-HMAC-SHA1.
    static func pbkdf2(password: String, salt: Data, iterations: Int, keyLength: Int) throws(CryptoError) -> Data {
        var derivedKey = Data(count: keyLength)
        let saltBytes = salt.withUnsafeBytes { [UInt8]($0) }

        let status = derivedKey.withUnsafeMutableBytes { keyBuffer -> CCCryptorStatus in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                password.utf8.count,
                saltBytes,
                saltBytes.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                UInt32(iterations),
                keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                keyLength
            )
        }

        guard status == kCCSuccess else {
            throw .keyDerivationFailed(status)
        }

        return derivedKey
    }
}

// MARK: - Crypto.Random

extension Crypto.Random {
    /// Generates cryptographically secure random bytes.
    static func data(length: Int) throws(CryptoError) -> Data {
        guard length > 0 else { return Data() }
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, length, baseAddress)
        }
        guard result == errSecSuccess else {
            throw .randomGenerationFailed
        }
        return data
    }
}
