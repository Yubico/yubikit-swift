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

import CommonCrypto
import Foundation

extension Data {

    /// Derives a key from a password using PBKDF2-HMAC-SHA1.
    /// - Parameters:
    ///   - password: The password string.
    ///   - salt: The salt data.
    ///   - iterations: Number of iterations (typically 1000+).
    ///   - keyLength: Desired key length in bytes.
    /// - Returns: The derived key.
    /// - Throws: `CryptoError.keyDerivationFailed` if derivation fails.
    internal static func pbkdf2(
        password: String,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws(CryptoError) -> Data {
        var derivedKey = Data(count: keyLength)
        let saltBytes = salt.withUnsafeBytes { [UInt8]($0) }

        let status = derivedKey.withUnsafeMutableBytes { keyBuffer -> CCCryptorStatus in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                password.utf8.count,
                saltBytes,
                saltBytes.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                UInt32(iterations),
                keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                keyLength
            )
        }

        guard status == kCCSuccess else {
            throw .keyDerivationFailed(status)
        }

        return derivedKey
    }
}
