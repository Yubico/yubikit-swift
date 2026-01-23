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

/// Elliptic Curve cryptographic key types and utilities.
/// Defines elliptic curve key types and utility methods for handling public and private keys for secp256r1 and secp384r1 curves.
public enum EC: Sendable {
    /// Supported elliptic curve types (currently secp256r1 and secp384r1) using uncompressed point representation.
    public enum Curve: Sendable, Equatable {
        case secp384r1
        case secp256r1

        /// The key size in bits for the selected curve.
        public var keySizeInBits: Int {
            switch self {
            case .secp256r1: return 256
            case .secp384r1: return 384
            }
        }

        /// The key size in bytes for the selected curve.
        public var keySizeInBytes: Int {
            keySizeInBits / 8
        }
    }

    /// An elliptic curve public key (x, y coordinates) on a supported curve.
    public struct PublicKey: Sendable, Equatable {
        /// The elliptic curve type (secp256r1 or secp384r1).
        public let curve: Curve

        /// The x coordinate of the public key point.
        public let x: Data  // x coordinate

        /// The y coordinate of the public key point.
        public let y: Data  // y coordinate

        /// Initialize a public key from its curve and coordinates.
        /// - Parameters:
        ///   - curve: The curve type.
        ///   - x: X coordinate as Data.
        ///   - y: Y coordinate as Data.
        public init(curve: Curve, x: Data, y: Data) {
            self.curve = curve
            self.x = x
            self.y = y
        }

        /// Initialize a public key from X9.63 format (0x04 || X || Y).
        /// - Parameters:
        ///   - x963Representation: The X9.63 encoded public key data.
        ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
        /// - Returns: PublicKey if valid, otherwise nil.
        public init?(x963Representation: Data, curve: Curve) {
            var data = x963Representation
            guard data.extract(1)?.bytes == [0x04] else {
                // invalid representation
                return nil
            }

            let coordSize = data.count / 2
            guard coordSize == curve.keySizeInBytes else {
                // Invalid length
                return nil
            }

            let x = data.extract(coordSize)!
            let y = data.extract(coordSize)!
            self.init(curve: curve, x: x, y: y)
        }

        /// X9.63 representation (0x04 || X || Y).
        public var x963Representation: Data {
            var result = Data([0x04])
            result.append(contentsOf: x)
            result.append(contentsOf: y)
            return result
        }
    }

    /// An elliptic curve private key with associated public key and secret scalar k.
    public struct PrivateKey: Sendable, Equatable {
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// The elliptic curve type, same as publicKey.curve.
        public var curve: Curve { publicKey.curve }

        /// The private scalar (k) for this key.
        public let k: Data  // secret scalar

        /// X9.63 representation of private key as 0x04 || X || Y || K.
        public var x963Representation: Data {
            publicKey.x963Representation + k
        }

        /// Initialize a private key from X9.63 format (0x04 || X || Y || K).
        /// - Parameters:
        ///   - x963Representation: The X9.63 encoded private key data.
        ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
        /// - Returns: PrivateKey if valid, otherwise nil.
        public init?(x963Representation: Data, curve: Curve) {
            var data = x963Representation
            guard data.extract(1)?.bytes == [0x04] else {
                // invalid representation
                return nil
            }

            let coordinateSizeInBytes = data.count / 3
            guard coordinateSizeInBytes == curve.keySizeInBytes,
                let x = data.extract(coordinateSizeInBytes),
                let y = data.extract(coordinateSizeInBytes),
                let k = data.extract(coordinateSizeInBytes)
            else {
                return nil
            }

            self.publicKey = .init(curve: curve, x: x, y: y)
            self.k = k
        }
    }
}
