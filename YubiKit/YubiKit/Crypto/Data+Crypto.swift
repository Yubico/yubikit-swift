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

/// Convenience extensions for cryptographic operations on Data.
extension Data {

    // MARK: - Hashing

    /// Computes SHA-1 hash.
    /// - Returns: 20-byte SHA-1 digest.
    /// - Note: SHA-1 is cryptographically weak and should only be used for legacy compatibility.
    internal func sha1() -> Data {
        Crypto.Hash.sha1(self)
    }

    /// Computes SHA-224 hash.
    /// - Returns: 28-byte SHA-224 digest.
    internal func sha224() -> Data {
        Crypto.Hash.sha224(self)
    }

    /// Computes SHA-256 hash.
    /// - Returns: 32-byte SHA-256 digest.
    internal func sha256() -> Data {
        Crypto.Hash.sha256(self)
    }

    /// Computes SHA-384 hash.
    /// - Returns: 48-byte SHA-384 digest.
    internal func sha384() -> Data {
        Crypto.Hash.sha384(self)
    }

    /// Computes SHA-512 hash.
    /// - Returns: 64-byte SHA-512 digest.
    internal func sha512() -> Data {
        Crypto.Hash.sha512(self)
    }

    // MARK: - HMAC

    /// Computes HMAC-SHA1.
    /// - Parameter key: The secret key.
    /// - Returns: 20-byte HMAC-SHA1 digest.
    internal func hmacSha1(key: Data) -> Data {
        Crypto.HMAC.sha1(self, key: key)
    }

    /// Computes HMAC-SHA256.
    /// - Parameter key: The secret key.
    /// - Returns: 32-byte HMAC-SHA256 digest.
    internal func hmacSha256(key: Data) -> Data {
        Crypto.HMAC.sha256(self, key: key)
    }

    // MARK: - AES Encryption

    /// Encrypts data using AES.
    /// - Parameters:
    ///   - key: The AES key.
    ///   - mode: Cipher mode (ECB or CBC with IV).
    /// - Returns: The encrypted data.
    internal func encryptAES(key: Data, mode: Crypto.BlockCipher.Mode) throws(CryptoError) -> Data {
        try Crypto.AES.encrypt(self, key: key, mode: mode)
    }

    /// Decrypts data using AES.
    /// - Parameters:
    ///   - key: The AES key.
    ///   - mode: Cipher mode (ECB or CBC with IV).
    /// - Returns: The decrypted data.
    internal func decryptAES(key: Data, mode: Crypto.BlockCipher.Mode) throws(CryptoError) -> Data {
        try Crypto.AES.decrypt(self, key: key, mode: mode)
    }

    // MARK: - 3DES Encryption

    /// Encrypts data using Triple DES.
    /// - Parameters:
    ///   - key: The 3DES key.
    ///   - mode: Cipher mode (ECB or CBC with IV).
    /// - Returns: The encrypted data.
    internal func encrypt3DES(key: Data, mode: Crypto.BlockCipher.Mode) throws(CryptoError) -> Data {
        try Crypto.TripleDES.encrypt(self, key: key, mode: mode)
    }

    /// Decrypts data using Triple DES.
    /// - Parameters:
    ///   - key: The 3DES key.
    ///   - mode: Cipher mode (ECB or CBC with IV).
    /// - Returns: The decrypted data.
    internal func decrypt3DES(key: Data, mode: Crypto.BlockCipher.Mode) throws(CryptoError) -> Data {
        try Crypto.TripleDES.decrypt(self, key: key, mode: mode)
    }

    /// Computes AES-CMAC.
    /// - Parameter key: The AES key.
    /// - Returns: 16-byte AES-CMAC.
    internal func aescmac(key: Data) throws(CryptoError) -> Data {
        try Crypto.AES.cmac(self, key: key)
    }

    /// Applies bit padding for CMAC.
    /// - Returns: Bit-padded data.
    internal func bitPadded() -> Data {
        Crypto.AES.bitPadded(self)
    }

    // MARK: - Key Derivation

    /// Derives a key using HKDF-SHA256.
    /// - Parameters:
    ///   - salt: The salt value.
    ///   - info: The context/application-specific info string.
    ///   - outputByteCount: The desired output key length in bytes.
    /// - Returns: The derived key material.
    internal func hkdfDeriveKey(salt: Data, info: String, outputByteCount: Int) -> Data {
        Crypto.KDF.hkdf(self, salt: salt, info: info, outputLength: outputByteCount)
    }

    /// Derives a key using HKDF-SHA256.
    /// - Parameters:
    ///   - salt: The salt value.
    ///   - info: The context/application-specific info data.
    ///   - outputByteCount: The desired output key length in bytes.
    /// - Returns: The derived key material.
    internal func hkdfDeriveKey(salt: Data, info: Data, outputByteCount: Int) -> Data {
        Crypto.KDF.hkdf(self, salt: salt, info: info, outputLength: outputByteCount)
    }

    // MARK: - Random

    /// Generates cryptographically secure random bytes.
    /// - Parameter length: Number of random bytes to generate.
    /// - Returns: Data containing random bytes.
    internal static func random(length: Int) throws(CryptoError) -> Data {
        try Crypto.Random.data(length: length)
    }

    // MARK: - Comparison

    /// Compares with another Data value in constant time to prevent timing attacks.
    /// - Parameter other: The data to compare with.
    /// - Returns: True if equal, false otherwise.
    internal func constantTimeCompare(_ other: Data) -> Bool {
        Crypto.constantTimeCompare(self, other)
    }
}
