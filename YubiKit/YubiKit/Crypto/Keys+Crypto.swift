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

    /// Computes ECDH shared secret with a peer's public key.
    /// - Parameter publicKey: The peer's EC public key.
    /// - Returns: The shared secret, or nil if key agreement fails.
    internal func sharedSecret(with publicKey: EC.PublicKey) -> Data? {
        Crypto.EC.sharedSecret(privateKey: self, publicKey: publicKey)
    }
}

// MARK: - RSA.PrivateKey

extension RSA.PrivateKey {

    /// Generates a random RSA private key.
    /// - Parameter keySize: The desired key size.
    /// - Returns: A new random RSA private key, or nil if generation fails.
    internal static func random(keySize: RSA.KeySize) -> RSA.PrivateKey? {
        guard let pkcs1 = Crypto.RSA.generateRandomPrivateKey(bitCount: keySize.rawValue) else {
            return nil
        }
        return RSA.PrivateKey(pkcs1: pkcs1)
    }
}

// MARK: - EC.PrivateKey

extension EC.PrivateKey {

    /// Generates a random EC private key.
    /// - Parameter curve: The desired elliptic curve.
    /// - Returns: A new random EC private key, or nil if generation fails.
    internal static func random(curve: EC.Curve) -> EC.PrivateKey? {
        guard let keyData = Crypto.EC.generateRandomPrivateKey(keySizeInBits: curve.keySizeInBits) else {
            return nil
        }
        return EC.PrivateKey(uncompressedRepresentation: keyData, curve: curve)
    }
}
