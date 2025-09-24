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

/// Features that may be supported by a PIV session depending on the YubiKey firmware version.
public enum PIVSessionFeature: SessionFeature, Sendable {

    /// PIN and touch policy support for PIV keys.
    case usagePolicy
    /// AES key management for PIV operations.
    case aesKey
    /// Serial number retrieval capability.
    case serialNumber
    /// Metadata storage and retrieval for PIV objects.
    case metadata
    /// Attestation certificate generation for PIV keys.
    case attestation
    /// P-384 elliptic curve support.
    case p384
    /// Cached touch policy support.
    case touchCached
    /// RSA key generation capability.
    case rsaGeneration
    /// RSA 3072 and 4096 bit key support.
    case rsa3072and4096
    /// Move and delete key operations.
    case moveDelete
    /// Ed25519 signature algorithm support.
    case ed25519
    /// X25519 key agreement algorithm support.
    case x25519

    /// Checks if this feature is supported by the given firmware version.
    /// - Parameter version: The YubiKey firmware version.
    /// - Returns: `true` if the feature is supported, `false` otherwise.
    public func isSupported(by version: Version) -> Bool {
        switch self {
        case .usagePolicy:
            return version >= Version("4.0.0")!
        case .aesKey:
            return version >= Version("5.4.0")!
        case .serialNumber:
            return version >= Version("5.0.0")!
        case .metadata:
            return version >= Version("5.3.0")!
        case .attestation:
            return version >= Version("4.3.0")!
        case .p384:
            return version >= Version("4.0.0")!
        case .touchCached:
            return version >= Version("4.3.0")!
        case .rsaGeneration:
            return version < Version("4.2.6")! || version >= Version("4.3.5")!
        case .rsa3072and4096:
            return version >= Version("5.7.0")!
        case .moveDelete:
            return version >= Version("5.7.0")!
        case .ed25519:
            return version >= Version("5.7.0")!
        case .x25519:
            return version >= Version("5.7.0")!
        }
    }
}
