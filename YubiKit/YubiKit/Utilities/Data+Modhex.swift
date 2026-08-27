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

// MARK: - Modhex

/// The modhex alphabet, in nibble order.
///
/// Yubico OTP output is typed by the YubiKey as if it were a keyboard, so it may only use
/// characters that land on the same physical key across the common keyboard layouts. Modhex is that
/// restricted alphabet: sixteen letters standing in for the sixteen hex digits.
private let modhexAlphabet = Array("cbdefghijklnrtuv")

/// ``modhexAlphabet`` reversed, for decoding. Mirrors the lookup table yubikit-android builds in
/// `Modhex`'s static initializer.
private let modhexNibbles = Dictionary(
    uniqueKeysWithValues: modhexAlphabet.enumerated().map { ($1, UInt8($0)) }
)

extension Data {

    /// Encodes as a modhex string, two characters per byte.
    public var modhexEncodedString: String {
        var result = ""
        result.reserveCapacity(count * 2)
        for byte in self {
            result.append(modhexAlphabet[Int(byte >> 4)])
            result.append(modhexAlphabet[Int(byte & 0x0F)])
        }
        return result
    }

    /// Decodes a modhex string.
    ///
    /// Decoding is case-insensitive. Returns `nil` if the string has an odd length or contains a
    /// character outside the modhex alphabet.
    public init?(modhexEncoded string: String) {
        let characters = string.lowercased()
        let nibbles = characters.compactMap { modhexNibbles[$0] }
        // A shorter result means `compactMap` dropped a character outside the alphabet.
        guard nibbles.count == characters.count, nibbles.count.isMultiple(of: 2) else { return nil }
        self.init(
            stride(from: 0, to: nibbles.count, by: 2).map { nibbles[$0] << 4 | nibbles[$0 + 1] }
        )
    }
}
