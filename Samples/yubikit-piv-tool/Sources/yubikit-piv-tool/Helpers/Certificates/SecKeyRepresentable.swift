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
import Security
import YubiKit

protocol SecKeyRepresentable {
    func makeSecKey() -> SecKey?
}

extension RSA.PublicKey: SecKeyRepresentable {
    // Convert YubiKit RSA public key to macOS SecKey
    func makeSecKey() -> SecKey? {
        var attrs: [String: Any] = [:]

        // Set RSA key attributes for Security framework
        attrs[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        attrs[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        attrs[kSecAttrKeySizeInBits as String] = size.inBits

        // RSA keys use full SPKI DER structure
        let keyData = der

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &err)
    }
}

extension EC.PublicKey: SecKeyRepresentable {
    // Convert YubiKit EC public key to macOS SecKey
    func makeSecKey() -> SecKey? {
        var attrs: [String: Any] = [:]

        // Set elliptic curve key attributes for Security framework
        attrs[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
        attrs[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        attrs[kSecAttrKeySizeInBits as String] = curve.keySizeInBits

        // EC keys require raw uncompressed point data (0x04 || X || Y)
        let keyData = uncompressedPoint

        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &err)
    }
}
