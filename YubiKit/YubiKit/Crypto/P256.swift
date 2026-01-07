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

// MARK: - Crypto.P256

extension Crypto.P256 {

    /// A P-256 key pair for ECDH key agreement.
    struct KeyPair: Sendable {
        private let privateKey: CryptoKit.P256.KeyAgreement.PrivateKey

        /// Creates a new random P-256 key pair.
        init() {
            self.privateKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        }

        /// The public key's X coordinate (32 bytes).
        var publicKeyX: Data {
            let raw = privateKey.publicKey.x963Representation
            return Data(raw.dropFirst().prefix(32))
        }

        /// The public key's Y coordinate (32 bytes).
        var publicKeyY: Data {
            let raw = privateKey.publicKey.x963Representation
            return Data(raw.dropFirst(33))
        }

        /// Performs ECDH key agreement with a peer's public key.
        /// - Parameter peerPublicKey: The peer's public key in X9.63 uncompressed format (65 bytes: 0x04 || X || Y).
        /// - Returns: The raw shared secret (32 bytes).
        /// - Throws: `CryptoError` if the peer key is invalid or key agreement fails.
        func sharedSecret(withX963 peerPublicKey: Data) throws(CryptoError) -> Data {
            guard let peerKey = try? CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey) else {
                throw .invalidKey
            }
            guard let secret = try? privateKey.sharedSecretFromKeyAgreement(with: peerKey) else {
                throw .keyAgreementFailed
            }
            return secret.withUnsafeBytes { Data($0) }
        }

        /// Performs ECDH key agreement with a peer's public key coordinates.
        /// - Parameters:
        ///   - x: The peer's public key X coordinate (32 bytes).
        ///   - y: The peer's public key Y coordinate (32 bytes).
        /// - Returns: The raw shared secret (32 bytes).
        /// - Throws: `CryptoError` if the peer key is invalid or key agreement fails.
        func sharedSecret(withX x: Data, y: Data) throws(CryptoError) -> Data {
            var uncompressed = Data([0x04])
            uncompressed.append(x)
            uncompressed.append(y)
            return try sharedSecret(withX963: uncompressed)
        }
    }
}
