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

extension YubiOTP {

    /// The modhex encoding of Yubico OTP.
    ///
    /// Modhex is the keyboard-layout-independent hexadecimal alphabet of Yubico OTP. It encodes each
    /// byte as two characters from `cbdefghijklnrtuv`.
    public enum Modhex {

        /// Encodes data as a modhex string, two characters per byte.
        ///
        /// - Parameter data: The data to encode.
        /// - Returns: The modhex string.
        public static func encode(_ data: Data) -> String {
            var result = ""
            result.reserveCapacity(data.count * 2)
            for byte in data {
                result.append(modhexAlphabet[Int(byte >> 4)])
                result.append(modhexAlphabet[Int(byte & 0x0F)])
            }
            return result
        }

        /// Decodes a modhex string.
        ///
        /// Decoding is case-insensitive.
        ///
        /// - Parameter string: The modhex string to decode.
        /// - Returns: The decoded data, or `nil` if the string has an odd length or contains a character
        ///   outside the modhex alphabet.
        public static func decode(_ string: String) -> Data? {
            let characters = string.lowercased()
            let nibbles = characters.compactMap { modhexNibbles[$0] }
            guard nibbles.count == characters.count, nibbles.count.isMultiple(of: 2) else { return nil }
            return Data(stride(from: 0, to: nibbles.count, by: 2).map { nibbles[$0] << 4 | nibbles[$0 + 1] })
        }
    }
}

private let modhexAlphabet = Array("cbdefghijklnrtuv")

private let modhexNibbles = Dictionary(
    uniqueKeysWithValues: modhexAlphabet.enumerated().map { ($1, UInt8($0)) }
)
