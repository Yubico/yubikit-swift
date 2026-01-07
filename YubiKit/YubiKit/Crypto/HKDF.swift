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

extension Data {

    /// Derives a key using HKDF-SHA256.
    /// - Parameters:
    ///   - salt: The salt value (can be empty).
    ///   - info: The context/application-specific info string.
    ///   - outputByteCount: The desired output key length in bytes.
    /// - Returns: The derived key material.
    internal func hkdfDeriveKey(salt: Data, info: String, outputByteCount: Int) -> Data {
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: self),
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: outputByteCount
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }

    /// Derives a key using HKDF-SHA256 with Data info parameter.
    /// - Parameters:
    ///   - salt: The salt value (can be empty).
    ///   - info: The context/application-specific info data.
    ///   - outputByteCount: The desired output key length in bytes.
    /// - Returns: The derived key material.
    internal func hkdfDeriveKey(salt: Data, info: Data, outputByteCount: Int) -> Data {
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: self),
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }
}
