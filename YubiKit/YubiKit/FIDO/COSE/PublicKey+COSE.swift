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

// MARK: - COSE Key Decoding

extension PublicKey {
    /// Initialize a PublicKey from a COSE.Key.
    ///
    /// Supports the following COSE key types:
    /// - EC2 with P-256 (crv=1) or P-384 (crv=2)
    /// - OKP with Ed25519 (crv=6) or X25519 (crv=4)
    /// - RSA (any algorithm — key material is algorithm-independent)
    ///
    /// - Parameter cose: COSE Key containing key type and parameters
    public init?(cose: COSE.Key) {
        switch cose {
        case .ec2(_, _, let crv, let x, let y):
            // Support P-256 and P-384
            let curve: EC.Curve
            switch crv {
            case 1:  // P-256
                curve = .secp256r1
            case 2:  // P-384
                curve = .secp384r1
            default:
                return nil
            }

            guard x.count == curve.keySizeInBytes,
                y.count == curve.keySizeInBytes
            else {
                return nil
            }

            self = .ec(EC.PublicKey(curve: curve, x: x, y: y))

        case .okp(_, _, let crv, let x):
            // Distinguish between Ed25519 (signing) and X25519 (key agreement)
            switch crv {
            case 6:  // Ed25519 - for use with EdDSA
                guard let ed25519Key = Ed25519.PublicKey(keyData: x) else {
                    return nil
                }
                self = .ed25519(ed25519Key)

            case 4:  // X25519 - for use with ECDH
                guard let x25519Key = X25519.PublicKey(keyData: x) else {
                    return nil
                }
                self = .x25519(x25519Key)

            default:
                return nil  // Ed448 (crv=7), X448 (crv=5) not supported
            }

        case .rsa(_, _, let n, let e):
            guard let rsaKey = RSA.PublicKey(n: n, e: e) else {
                return nil
            }
            self = .rsa(rsaKey)

        case .other:
            // Unsupported key type or algorithm - cannot convert to PublicKey
            return nil
        }
    }
}
