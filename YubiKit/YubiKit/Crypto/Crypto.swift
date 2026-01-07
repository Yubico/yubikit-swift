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

    // MARK: - Constants

    /// AES block size in bytes.
    static let aesBlockSize = kCCBlockSizeAES128

    /// SHA-1 block size in bytes.
    static let sha1BlockSize = Int(CC_SHA1_BLOCK_BYTES)

    /// SHA-256 block size in bytes.
    static let sha256BlockSize = Int(CC_SHA256_BLOCK_BYTES)

    /// SHA-512 block size in bytes.
    static let sha512BlockSize = Int(CC_SHA512_BLOCK_BYTES)

    // MARK: - Symmetric Algorithms

    /// Symmetric encryption algorithms.
    enum SymmetricAlgorithm: Sendable {
        case aes
        case tripleDES

        fileprivate var ccAlgorithm: CCAlgorithm {
            switch self {
            case .aes: return CCAlgorithm(kCCAlgorithmAES)
            case .tripleDES: return CCAlgorithm(kCCAlgorithm3DES)
            }
        }

        fileprivate var blockSize: Int {
            switch self {
            case .aes: return kCCBlockSizeAES128
            case .tripleDES: return kCCBlockSize3DES
            }
        }
    }

    // MARK: - Hashing

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
            if let rawHashPtr = hashPtr.baseAddress {
                data.withUnsafeBytes { dataPtr in
                    if let rawDataPtr = dataPtr.baseAddress {
                        _ = CC_SHA224(rawDataPtr, CC_LONG(data.count), rawHashPtr)
                    }
                }
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

    // MARK: - HMAC

    /// Computes HMAC-SHA1.
    /// - Note: HMAC-SHA1 is used for legacy compatibility (e.g., OATH TOTP/HOTP).
    static func hmacSha1(_ data: Data, key: Data) -> Data {
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }

    /// Computes HMAC-SHA256.
    static func hmacSha256(_ data: Data, key: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }

    // MARK: - Symmetric Encryption

    /// Encrypts data using symmetric encryption.
    static func encrypt(
        _ data: Data,
        using algorithm: SymmetricAlgorithm,
        key: Data,
        iv: Data? = nil
    ) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try cryptOperation(kCCEncrypt, data: data, algorithm: algorithm.ccAlgorithm, mode: mode, key: key, iv: iv)
    }

    /// Decrypts data using symmetric encryption.
    static func decrypt(
        _ data: Data,
        using algorithm: SymmetricAlgorithm,
        key: Data,
        iv: Data? = nil
    ) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try cryptOperation(kCCDecrypt, data: data, algorithm: algorithm.ccAlgorithm, mode: mode, key: key, iv: iv)
    }

    /// Computes AES-CMAC.
    static func aesCmac(_ data: Data, key: Data) throws(CryptoError) -> Data {
        let blockSize = kCCBlockSizeAES128
        let constZero = Data(count: blockSize)
        let constRb = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
        ])
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)

        let l = try cryptOperation(kCCEncrypt, data: constZero, algorithm: algorithm, mode: CCMode(kCCModeCBC), key: key, iv: constZero)
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
            let encryptedBlock = try cryptOperation(
                kCCEncrypt,
                data: messageSkippingLastBlock,
                algorithm: algorithm,
                mode: CCMode(kCCModeCBC),
                key: key,
                iv: constZero
            ).subdata(in: (messageSkippingLastBlock.count - blockSize)..<messageSkippingLastBlock.count)
            lastIv = lastIv.xor(with: encryptedBlock)
        }

        return try cryptOperation(kCCEncrypt, data: lastBlock, algorithm: algorithm, mode: CCMode(kCCModeCBC), key: key, iv: lastIv)
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

    // MARK: - Key Derivation

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

    // MARK: - Random

    /// Generates cryptographically secure random bytes.
    static func randomData(length: Int) throws(CryptoError) -> Data {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, length, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw .randomGenerationFailed
        }
        return data
    }

    // MARK: - Comparison

    /// Compares two Data values in constant time to prevent timing attacks.
    static func constantTimeCompare(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    // MARK: - Private Helpers

    private static func cryptOperation(
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
                        CCCryptorCreateWithMode(
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
                        return CCCryptorUpdate(
                            cryptorRef,
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
