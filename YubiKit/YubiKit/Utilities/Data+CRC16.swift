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

// The residual a CRC-16 leaves over a buffer that already carries its own trailing
// checksum. Used to validate OTP data responses.
private let crc16OKResidual: UInt16 = 0xF0B8

extension Data {

    /// The CRC-16 used by the Yubico OTP protocol (reflected CCITT, polynomial `0x8408`,
    /// initial value `0xFFFF`).
    var crc16: UInt16 {
        var crc: UInt16 = 0xFFFF
        for byte in self {
            crc ^= UInt16(byte)
            for _ in 0..<8 {
                let lsb = crc & 1
                crc >>= 1
                if lsb == 1 { crc ^= 0x8408 }
            }
        }
        return crc
    }

    /// Whether this buffer, which must already end with its own CRC-16, checksums correctly.
    var hasValidCRC16: Bool {
        crc16 == crc16OKResidual
    }

    /// This buffer with its OTP CRC-16 trailer appended, little-endian.
    ///
    /// The OTP protocol stores the *complement* of the checksum, so that recomputing the CRC over
    /// the result yields ``crc16OKResidual``.
    var appendingCRC16: Data {
        let complement = ~crc16
        return self + Data([UInt8(complement & 0xFF), UInt8(complement >> 8)])
    }
}
