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
import Testing

@testable import YubiKit

/// Vectors ported from yubikit-android's `ChecksumUtilsTest.java`; the residual property is the
/// one `yubikit.core.otp.check_crc` relies on.
struct CRC16Tests {

    @Test(
        "CRC-16 matches the reference vectors",
        arguments: [
            (Data([0x00, 0x01, 0x02, 0x03, 0x04]), UInt16(62_919)),
            (Data([0xFE]), UInt16(4_470)),
            (
                Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x30, 0x75, 0x00, 0x09, 0x3D, 0xFA, 0x60, 0xEA]),
                UInt16(35_339)
            ),
            (Data([0x55, 0xAA, 0x00, 0xFF]), UInt16(52_149)),
        ]
    )
    func referenceVectors(data: Data, expected: UInt16) {
        #expect(data.crc16 == expected)
    }

    @Test("appending the CRC-16 trailer produces a buffer that validates")
    func residualHolds() {
        for data in [
            Data([0x00, 0x01, 0x02, 0x03, 0x04]),
            Data([0xFE]),
            Data([0x55, 0xAA, 0x00, 0xFF]),
            Data(),
            Data(repeating: 0, count: 64),
        ] {
            #expect(data.appendingCRC16.hasValidCRC16, "residual should hold for \(data.count) bytes")
        }
    }

    @Test("a corrupted buffer fails the CRC check")
    func corruptionDetected() {
        var corrupted = Data([0x01, 0x02, 0x03, 0x04]).appendingCRC16
        corrupted[0] ^= 0xFF
        #expect(!corrupted.hasValidCRC16)
    }

    @Test("the CRC trailer is little-endian and stores the complement")
    func trailerLayout() {
        let payload = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let complement = ~payload.crc16  // 62919 -> 0x0A38
        let trailer = payload.appendingCRC16.suffix(2)
        #expect(Array(trailer) == [UInt8(complement & 0xFF), UInt8(complement >> 8)])
    }
}
