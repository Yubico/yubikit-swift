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

extension Data {

    /// Generates cryptographically secure random bytes.
    /// - Parameter count: Number of random bytes to generate.
    /// - Returns: Data containing random bytes.
    /// - Throws: `CryptoError.randomGenerationFailed` if SecRandomCopyBytes fails.
    internal static func secureRandom(count: Int) throws(CryptoError) -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw .randomGenerationFailed
        }
        return data
    }
}
