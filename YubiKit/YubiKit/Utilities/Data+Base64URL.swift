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

// MARK: - Data Base64URL

extension Data {

    /// Encode as base64url string (RFC 4648 §5, no padding).
    internal func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode from base64url string.
    internal init?(base64URLEncoded string: String) {
        var base64 =
            string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        self.init(base64Encoded: base64)
    }
}

// MARK: - Codable Helpers

extension KeyedDecodingContainer {

    /// Decode a required base64url-encoded `Data` value.
    internal func decodeBase64URL(forKey key: Key) throws -> Data {
        let string = try decode(String.self, forKey: key)
        guard let data = Data(base64URLEncoded: string) else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: self,
                debugDescription: "Invalid base64url string"
            )
        }
        return data
    }

    /// Decode an optional base64url-encoded `Data` value.
    internal func decodeBase64URLIfPresent(forKey key: Key) throws -> Data? {
        guard let string = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let data = Data(base64URLEncoded: string) else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: self,
                debugDescription: "Invalid base64url string"
            )
        }
        return data
    }
}

extension KeyedEncodingContainer {

    /// Encode a `Data` value as a base64url string.
    internal mutating func encodeBase64URL(_ value: Data, forKey key: Key) throws {
        try encode(value.base64URLEncodedString(), forKey: key)
    }

    /// Encode an optional `Data` value as a base64url string.
    internal mutating func encodeBase64URLIfPresent(_ value: Data?, forKey key: Key) throws {
        try encodeIfPresent(value?.base64URLEncodedString(), forKey: key)
    }
}
