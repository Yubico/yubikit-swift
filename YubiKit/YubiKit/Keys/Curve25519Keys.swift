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

/// Ed25519
public enum Ed25519: Sendable {
    /// An Ed25519 public key for signature verification
    public struct PublicKey: Sendable, Equatable {
        /// The 32-byte public key data
        public let keyData: Data

        /// Initialize an Ed25519 public key from raw key data
        /// - Parameter keyData: 32-byte Ed25519 public key
        public init?(keyData: Data) {
            guard keyData.count == 32 else { return nil }
            guard Curve25519Crypto.isValidEd25519PublicKey(keyData) else { return nil }
            self.keyData = keyData
        }
    }

    /// An Ed25519 private key for signing operations
    public struct PrivateKey: Sendable, Equatable {
        /// The associated public key
        public let publicKey: PublicKey
        /// The 32-byte private key seed
        public let seed: Data

        /// Initialize an Ed25519 private key from seed and public key
        /// - Parameters:
        ///   - seed: 32-byte private key seed
        ///   - publicKey: Associated public key
        public init?(seed: Data, publicKey: PublicKey) {
            guard seed.count == 32 else { return nil }
            guard Curve25519Crypto.validateEd25519KeyPair(seed: seed, publicKey: publicKey.keyData) else {
                return nil
            }
            self.seed = seed
            self.publicKey = publicKey
        }

        /// Initialize an Ed25519 private key from seed data, deriving public key
        /// - Parameter seed: 32-byte private key seed
        public init?(seed: Data) {
            guard seed.count == 32 else { return nil }
            guard let derivedPublicKey = Curve25519Crypto.deriveEd25519PublicKey(fromSeed: seed),
                  let publicKey = PublicKey(keyData: derivedPublicKey)
            else {
                return nil
            }
            self.seed = seed
            self.publicKey = publicKey
        }
    }
}

/// X25519 key agreement algorithm keys
public enum X25519: Sendable {
    /// An X25519 public key for key agreement
    public struct PublicKey: Sendable, Equatable {
        /// The 32-byte public key data
        public let keyData: Data

        /// Initialize an X25519 public key from raw key data
        /// - Parameter keyData: 32-byte X25519 public key
        public init?(keyData: Data) {
            guard keyData.count == 32 else { return nil }
            guard Curve25519Crypto.isValidX25519PublicKey(keyData) else { return nil }
            self.keyData = keyData
        }
    }

    /// An X25519 private key for key agreement operations
    public struct PrivateKey: Sendable, Equatable {
        /// The associated public key
        public let publicKey: PublicKey
        /// The 32-byte private key scalar
        public let scalar: Data

        /// Initialize an X25519 private key from scalar and public key
        /// - Parameters:
        ///   - scalar: 32-byte private key scalar
        ///   - publicKey: Associated public key
        public init?(scalar: Data, publicKey: PublicKey) {
            guard scalar.count == 32 else { return nil }
            guard Curve25519Crypto.validateX25519KeyPair(scalar: scalar, publicKey: publicKey.keyData) else {
                return nil
            }
            self.scalar = scalar
            self.publicKey = publicKey
        }

        /// Initialize an X25519 private key from scalar data, deriving public key
        /// - Parameter scalar: 32-byte private key scalar
        public init?(scalar: Data) {
            guard scalar.count == 32 else { return nil }
            guard let derivedPublicKey = Curve25519Crypto.deriveX25519PublicKey(fromScalar: scalar),
                  let publicKey = PublicKey(keyData: derivedPublicKey)
            else {
                return nil
            }
            self.scalar = scalar
            self.publicKey = publicKey
        }
    }
}
