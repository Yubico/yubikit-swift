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

/// # Curve25519Keys
/// Defines Ed25519 (signing) and X25519 (key agreement) key types following RFC 8410 specifications.

import CryptoKit
import Foundation

public enum Curve25519 {

    /// Ed25519 digital signature algorithm keys (RFC 8410)
    public enum Ed25519 {
        /// An Ed25519 public key for signature verification
        public struct PublicKey: Sendable, Equatable {
            /// The 32-byte public key data
            public let keyData: Data

            /// Initialize an Ed25519 public key from raw key data
            /// - Parameter keyData: 32-byte Ed25519 public key
            public init?(keyData: Data) {

                // Let's check if CryptoKit agrees this is a valid key
                guard let _ = try? CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
                    return nil
                }

                guard keyData.count == 32 else { return nil }
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

                // Validate that the seed and public key are consistent using CryptoKit
                guard let cryptoKitPrivateKey = try? CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: seed),
                    cryptoKitPrivateKey.publicKey.rawRepresentation == publicKey.keyData
                else {
                    return nil
                }

                self.seed = seed
                self.publicKey = publicKey
            }

            /// Initialize an Ed25519 private key from seed data, deriving public key
            /// - Parameter seed: 32-byte private key seed
            public init?(seed: Data) {
                guard seed.count == 32 else { return nil }

                // Use CryptoKit to derive the public key from the private key seed
                guard let cryptoKitPrivateKey = try? CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: seed),
                    let publicKey = PublicKey(keyData: cryptoKitPrivateKey.publicKey.rawRepresentation)
                else {
                    return nil
                }

                self.seed = seed
                self.publicKey = publicKey
            }
        }
    }

    /// X25519 key agreement algorithm keys (RFC 8410)
    public enum X25519 {
        /// An X25519 public key for key agreement
        public struct PublicKey: Sendable, Equatable {
            /// The 32-byte public key data
            public let keyData: Data

            /// Initialize an X25519 public key from raw key data
            /// - Parameter keyData: 32-byte X25519 public key
            public init?(keyData: Data) {
                guard keyData.count == 32 else { return nil }

                // Validate with CryptoKit to ensure this is a valid X25519 public key
                guard let _ = try? CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData) else {
                    return nil
                }

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

                // Validate that the scalar and public key are consistent using CryptoKit
                guard
                    let cryptoKitPrivateKey = try? CryptoKit.Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: scalar
                    ),
                    cryptoKitPrivateKey.publicKey.rawRepresentation == publicKey.keyData
                else {
                    return nil
                }

                self.scalar = scalar
                self.publicKey = publicKey
            }

            /// Initialize an X25519 private key from scalar data, deriving public key
            /// - Parameter scalar: 32-byte private key scalar
            public init?(scalar: Data) {
                guard scalar.count == 32 else { return nil }

                // Use CryptoKit to derive the public key from the private key scalar
                guard
                    let cryptoKitPrivateKey = try? CryptoKit.Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: scalar
                    ),
                    let publicKey = PublicKey(keyData: cryptoKitPrivateKey.publicKey.rawRepresentation)
                else {
                    return nil
                }

                self.scalar = scalar
                self.publicKey = publicKey
            }
        }
    }
}
