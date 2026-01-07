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

    /// Computes HMAC-SHA1 authentication code.
    /// - Parameter key: The secret key for HMAC.
    /// - Returns: 20-byte HMAC-SHA1 digest.
    /// - Note: HMAC-SHA1 is used for legacy compatibility (e.g., OATH TOTP/HOTP).
    internal func hmacSha1(key: Data) -> Data {
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(
            for: self,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }

    /// Computes HMAC-SHA256 authentication code.
    /// - Parameter key: The secret key for HMAC.
    /// - Returns: 32-byte HMAC-SHA256 digest.
    internal func hmacSha256(key: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(
            for: self,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }
}
