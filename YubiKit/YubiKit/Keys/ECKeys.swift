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
/// Defines elliptic curve key types and utility methods for handling public and private keys for P-256 and P-384 curves.
public enum EC: Sendable {
    /// Supported elliptic curve types (currently P-256 and P-384) using uncompressed point representation.
    public enum Curve: Sendable, Equatable {
        case p384
        case p256

        /// The key size in bits for the selected curve.
        public var keySizeInBits: Int {
            switch self {
            case .p256: return 256
            case .p384: return 384
            }
        }

        /// The key size in bytes for the selected curve.
        public var keySizeInBytes: Int {
            keySizeInBits / 8
        }
    }

    /// An elliptic curve public key (x, y coordinates) on a supported curve.
    public struct PublicKey: Sendable, Equatable {
        /// The elliptic curve type (P-256 or P-384).
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

        /// Initialize a public key from SEC1 uncompressed EC point format (0x04 || X || Y).
        /// - Parameter uncompressedPoint: Data in SEC1 format.
        /// - Returns: PublicKey if valid, otherwise nil.
        public init?(uncompressedPoint: Data) {
            var data = uncompressedPoint
            guard data.extract(1)?.bytes == [0x04] else {
                // invalid representation
                return nil
            }

            let coordSize = data.count / 2
            guard let curve = Curve(coordinateSize: coordSize) else {
                // Invalid length
                return nil
            }

            let x = data.extract(coordSize)!
            let y = data.extract(coordSize)!
            self.init(curve: curve, x: x, y: y)
        }

        /// SEC1 uncompressed EC point representation (0x04 || X || Y).
        public var uncompressedPoint: Data {
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

        /// Uncompressed representation of private key as 0x04 || X || Y || K.
        public var uncompressedRepresentation: Data {
            publicKey.uncompressedPoint + k
        }

        /// Initialize a private key from 0x04 || X || Y || K
        /// - Parameter uncompressedRepresentation: uncompressedPoint + K
        /// - Returns: PrivateKey if valid, otherwise nil.
        public init?(uncompressedRepresentation: Data) {
            var data = uncompressedRepresentation
            guard data.extract(1)?.bytes == [0x04] else {
                // invalid representation
                return nil
            }

            let coordinateSizeInBytes = data.count / 3
            guard let curve = Curve(coordinateSize: coordinateSizeInBytes),
                let x = data.extract(coordinateSizeInBytes),  // x
                let y = data.extract(coordinateSizeInBytes),  // y
                let k = data.extract(coordinateSizeInBytes)  // k
            else {
                return nil
            }

            self.publicKey = .init(curve: curve, x: x, y: y)
            self.k = k
        }
    }
}

// MARK: - Private helpers
extension EC.Curve {
    // Initialize a curve type based on the byte length of a coordinate.
    // - Parameter bytesCount: Length in bytes of a single coordinate (x or y).
    // - Returns: Matching curve if found, or nil if not supported.
    fileprivate init?(coordinateSize bytesCount: Int) {
        switch bytesCount {
        case EC.Curve.p256.keySizeInBytes:
            self = .p256
        case EC.Curve.p384.keySizeInBytes:
            self = .p384
        default:
            return nil
        }
    }
}
