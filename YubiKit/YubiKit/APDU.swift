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

/// Data model for encapsulating an APDU command, as defined by the ISO/IEC 7816-4 standard.
struct APDU: Sendable, CustomStringConvertible {

    let cla: UInt8
    let ins: UInt8
    let p1: UInt8
    let p2: UInt8
    let command: Data?

    /// Creates an APDU struct.
    /// - Parameters:
    ///   - cla: The instruction class.
    ///   - ins: The instruction code.
    ///   - p1: The first instruction parameter byte.
    ///   - p2: The second instruction parameter byte.
    ///   - command: The command data.
    init(
        cla: UInt8,
        ins: UInt8,
        p1: UInt8,
        p2: UInt8,
        command: Data? = nil
    ) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.command = command
    }

    /// The raw APDU data bytes ready for transmission to the card.
    var data: Data {
        var data = Data()
        data.append(cla)
        data.append(ins)
        data.append(p1)
        data.append(p2)

        guard let command = command, command.count > 0 else {
            // 4 bytes: "Case 1" APDU
            return data
        }

        let isShort = command.count < UInt8.max

        if isShort {
            let length = UInt8(command.count)
            data.append(length)
            data.append(command)
        } else {
            let lengthHigh: UInt8 = UInt8(command.count / 256)
            let lengthLow: UInt8 = UInt8(command.count % 256)
            data.append(0x00)
            data.append(lengthHigh)
            data.append(lengthLow)
            data.append(command)
        }

        return data
    }

    /// A string representation of the APDU for debugging purposes.
    var description: String {
        "APDU(cla: \(cla.hexValue), ins: \(ins.hexValue), p1: \(p1.hexValue), p2: \(p2.hexValue), command: \(command?.hexEncodedString ?? "nil")"
    }
}
