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

/// # RSAKeys+SecHelpers
/// Integration helpers between the RSA key types and Apple's Security framework (`SecKey`).
/// Provides conversion and random key generation for interoperability with native APIs.

import Foundation
import Security

public extension RSA.PrivateKey {
    /// Generate a random RSA private key of the specified size using Apple's Security framework.
    /// - Parameter keySize: Desired RSA key size.
    /// - Returns: A valid RSA.PrivateKey or nil if generation / parsing fails.
    static func random(keySize: RSA.KeySize) -> RSA.PrivateKey? {
        let attributes: [CFString : Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: keySize.rawValue
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let _ = SecKeyCopyPublicKey(secKey) else {
            return nil
        }

        guard let pkcs1 = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            return nil
        }

        return RSA.PrivateKey(pkcs1: pkcs1)
    }
}

public extension RSA.PublicKey {
    /// Convert this RSA public key to a native SecKey.
    /// - Returns: A SecKey suitable for cryptographic operations, or nil if conversion fails.
    func asSecKey() -> SecKey? {
        let attributes: [CFString : Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size.rawValue
        ]

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &err)
    }
}

public extension RSA.PrivateKey {
    /// Convert this RSA private key to a native SecKey.
    /// - Returns: A SecKey suitable for cryptographic operations, or nil if conversion fails.
    func asSecKey() -> SecKey? {
        let attributes: [CFString : Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size.rawValue
        ]

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &err)
    }
}
