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

/// Convenience extensions for cryptographic operations on key types.

// MARK: - EC.PrivateKey

extension EC.PrivateKey {

    /// Generates a random EC private key.
    /// - Parameter curve: The desired elliptic curve.
    /// - Returns: A new random EC private key.
    /// - Throws: `CryptoError.keyCreationFailed` if generation fails.
    internal static func random(curve: EC.Curve) throws(CryptoError) -> EC.PrivateKey {
        let keyData = try Crypto.EC.generateRandomPrivateKey(curve: curve)
        guard let key = EC.PrivateKey(uncompressedRepresentation: keyData, curve: curve) else {
            throw .keyCreationFailed(nil)
        }
        return key
    }

    /// Computes ECDH shared secret with a peer's public key.
    /// - Parameter publicKey: The peer's EC public key.
    /// - Returns: The shared secret.
    /// - Throws: `CryptoError.keyCreationFailed` or `CryptoError.keyAgreementFailed`.
    internal func sharedSecret(with publicKey: EC.PublicKey) throws(CryptoError) -> Data {
        try Crypto.EC.sharedSecret(privateKey: self, publicKey: publicKey)
    }
}

// MARK: - EC.PublicKey

extension EC.PublicKey {

    /// Initialize a public key from separate X and Y coordinates.
    /// - Parameters:
    ///   - x: The X coordinate.
    ///   - y: The Y coordinate.
    ///   - curve: The elliptic curve.
    /// - Throws: `CryptoError.invalidKey` if coordinates are invalid for the curve.
    internal init(x: Data, y: Data, curve: EC.Curve) throws(CryptoError) {
        var uncompressed = Data([0x04])
        uncompressed.append(x)
        uncompressed.append(y)
        guard let key = EC.PublicKey(uncompressedPoint: uncompressed, curve: curve) else {
            throw .invalidKey
        }
        self = key
    }
}

// MARK: - RSA.PrivateKey

extension RSA.PrivateKey {

    /// Generates a random RSA private key.
    /// - Parameter keySize: The desired key size.
    /// - Returns: A new random RSA private key.
    /// - Throws: `CryptoError.keyCreationFailed` if generation fails.
    internal static func random(keySize: RSA.KeySize) throws(CryptoError) -> RSA.PrivateKey {
        let pkcs1 = try Crypto.RSA.generateRandomPrivateKey(bitCount: keySize.rawValue)
        guard let key = RSA.PrivateKey(pkcs1: pkcs1) else {
            throw .keyCreationFailed(nil)
        }
        return key
    }
}
