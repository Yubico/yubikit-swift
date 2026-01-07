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
import CryptoKit
import Foundation

extension Data {

    /// Computes SHA-1 hash of the data.
    /// - Returns: 20-byte SHA-1 digest.
    /// - Note: SHA-1 is cryptographically weak and should only be used for legacy compatibility.
    internal func sha1() -> Data {
        Data(Insecure.SHA1.hash(data: self))
    }

    /// Computes SHA-224 hash of the data.
    /// - Returns: 28-byte SHA-224 digest.
    /// - Note: CryptoKit doesn't include SHA-224, so we use CommonCrypto.
    internal func sha224() -> Data {
        var hash = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
        hash.withUnsafeMutableBytes { hashPtr in
            if let rawHashPtr = hashPtr.baseAddress {
                self.withUnsafeBytes { dataPtr in
                    if let rawDataPtr = dataPtr.baseAddress {
                        _ = CC_SHA224(rawDataPtr, CC_LONG(self.count), rawHashPtr)
                    }
                }
            }
        }
        return hash
    }

    /// Computes SHA-256 hash of the data.
    /// - Returns: 32-byte SHA-256 digest.
    internal func sha256() -> Data {
        Data(SHA256.hash(data: self))
    }

    /// Computes SHA-384 hash of the data.
    /// - Returns: 48-byte SHA-384 digest.
    internal func sha384() -> Data {
        Data(SHA384.hash(data: self))
    }

    /// Computes SHA-512 hash of the data.
    /// - Returns: 64-byte SHA-512 digest.
    internal func sha512() -> Data {
        Data(SHA512.hash(data: self))
    }
}
