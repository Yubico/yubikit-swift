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

import CryptoKit
import Foundation

/// Curve25519 key validation and derivation operations.
internal enum Curve25519Crypto {

    // MARK: - Ed25519 (Signing)

    /// Validates that the data represents a valid Ed25519 public key.
    /// - Parameter data: 32-byte public key data.
    /// - Returns: True if valid, false otherwise.
    static func isValidEd25519PublicKey(_ data: Data) -> Bool {
        (try? Curve25519.Signing.PublicKey(rawRepresentation: data)) != nil
    }

    /// Derives an Ed25519 public key from a private key seed.
    /// - Parameter seed: 32-byte private key seed.
    /// - Returns: The 32-byte public key, or nil if the seed is invalid.
    static func deriveEd25519PublicKey(fromSeed seed: Data) -> Data? {
        guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            return nil
        }
        return privateKey.publicKey.rawRepresentation
    }

    /// Validates that an Ed25519 seed and public key are consistent.
    /// - Parameters:
    ///   - seed: 32-byte private key seed.
    ///   - publicKey: 32-byte public key.
    /// - Returns: True if the public key matches the seed, false otherwise.
    static func validateEd25519KeyPair(seed: Data, publicKey: Data) -> Bool {
        guard let derivedPublicKey = deriveEd25519PublicKey(fromSeed: seed) else {
            return false
        }
        return derivedPublicKey == publicKey
    }

    // MARK: - X25519 (Key Agreement)

    /// Validates that the data represents a valid X25519 public key.
    /// - Parameter data: 32-byte public key data.
    /// - Returns: True if valid, false otherwise.
    static func isValidX25519PublicKey(_ data: Data) -> Bool {
        (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)) != nil
    }

    /// Derives an X25519 public key from a private key scalar.
    /// - Parameter scalar: 32-byte private key scalar.
    /// - Returns: The 32-byte public key, or nil if the scalar is invalid.
    static func deriveX25519PublicKey(fromScalar scalar: Data) -> Data? {
        guard let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar) else {
            return nil
        }
        return privateKey.publicKey.rawRepresentation
    }

    /// Validates that an X25519 scalar and public key are consistent.
    /// - Parameters:
    ///   - scalar: 32-byte private key scalar.
    ///   - publicKey: 32-byte public key.
    /// - Returns: True if the public key matches the scalar, false otherwise.
    static func validateX25519KeyPair(scalar: Data, publicKey: Data) -> Bool {
        guard let derivedPublicKey = deriveX25519PublicKey(fromScalar: scalar) else {
            return false
        }
        return derivedPublicKey == publicKey
    }
}
