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

// The ISO 13239 CRC-16 of the Yubico OTP protocol.
extension Data {

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

    var hasValidCRC16: Bool {
        crc16 == crc16OKResidual
    }

    var appendingCRC16: Data {
        let complement = ~crc16
        return self + Data([UInt8(complement & 0xFF), UInt8(complement >> 8)])
    }
}

// The CRC-16 of data followed by its complemented CRC-16.
private let crc16OKResidual: UInt16 = 0xF0B8
