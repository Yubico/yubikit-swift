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

import Shield
import YubiKit

// Map from Yubikit types to Sheild's AlgorithmIdentifier
extension AlgorithmIdentifier {
    init?(
        algorithm: PIV.HashAlgorithm,
        keyType: PIV.KeyType
    ) throws {
        let mapped: Digester.Algorithm =
            switch algorithm {
            case .sha1: .sha1
            case .sha224: .sha224
            case .sha256: .sha256
            case .sha384: .sha384
            case .sha512: .sha512
            }

        let signatureAlgorithm: AlgorithmIdentifier
        switch keyType {
        case .rsa:
            signatureAlgorithm = try AlgorithmIdentifier(digestAlgorithm: mapped, keyType: .rsa)
        case .ec:
            signatureAlgorithm = try AlgorithmIdentifier(digestAlgorithm: mapped, keyType: .ec)
        case .ed25519:
            // Ed25519 is not supported by Shield
            // TODO: Handle Ed25519 with a custom implementation
            return nil
        case .x25519:
            // Invalid key type for signing
            return nil
        }

        self = signatureAlgorithm
    }
}
