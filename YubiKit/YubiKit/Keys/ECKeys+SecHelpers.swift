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

/// # ECKeys+SecHelpers
/// Integration helpers between the EC key types and Apple's Security framework (`SecKey`).
/// Provides conversion and random key generation for interoperability with native APIs.

import Foundation
import Security

extension EC.PrivateKey {
    /// Generate a random EC private key of the specified curve using Apple's Security framework.
    /// - Parameter curve: Desired EC curve.
    /// - Returns: A valid EC.PrivateKey or nil if generation / parsing fails.
    public static func random(curve: EC.Curve) -> EC.PrivateKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let _ = SecKeyCopyPublicKey(secKey)
        else {
            return nil
        }

        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            return nil
        }

        return EC.PrivateKey(uncompressedRepresentation: keyData, curve: curve)
    }

    /// Convert this EC private key to a native SecKey.
    /// - Returns: A SecKey suitable for cryptographic operations, or nil if conversion fails.
    public func asSecKey() -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(
            uncompressedRepresentation as CFData,
            attributes as CFDictionary,
            &err
        )
    }
}

extension EC.PublicKey {
    /// Convert this EC public key to a native SecKey.
    /// - Returns: A SecKey suitable for cryptographic operations, or nil if conversion fails.
    public func asSecKey() -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(
            uncompressedPoint as CFData,
            attributes as CFDictionary,
            &err
        )
    }
}
