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

    /// The type of APDU command format.
    enum ApduType: Sendable {
        /// Short APDU format with data length up to 255 bytes.
        case short
        /// Extended APDU format supporting larger data payloads.
        case extended
    }

    let cla: UInt8
    let ins: UInt8
    let p1: UInt8
    let p2: UInt8
    let command: Data?
    let type: ApduType

    /// Creates an APDU struct.
    /// - Parameters:
    ///   - cla: The instruction class.
    ///   - ins: The instruction code.
    ///   - p1: The first instruction parameter byte.
    ///   - p2: The second instruction parameter byte.
    ///   - command: The command data.
    ///   - type: The type of the APDU, short or extended.
    init(
        cla: UInt8,
        ins: UInt8,
        p1: UInt8,
        p2: UInt8,
        command: Data? = nil,
        type: ApduType = .short
    ) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.command = command
        self.type = type
    }

    /// The raw APDU data bytes ready for transmission to the card.
    var data: Data {
        var data = Data()
        data.append(cla)
        data.append(ins)
        data.append(p1)
        data.append(p2)
        switch type {
        case .short:
            if let command = command, command.count > 0 {
                guard command.count < UInt8.max else { fatalError() }
                let length = UInt8(command.count)
                data.append(length)
                data.append(command)
            }
        case .extended:
            if let command = command, command.count > 0 {
                let lengthHigh: UInt8 = UInt8(command.count / 256)
                let lengthLow: UInt8 = UInt8(command.count % 256)
                data.append(0x00)
                data.append(lengthHigh)
                data.append(lengthLow)
                data.append(command)
            } else {
                data.append(0x00)
                data.append(0x00)
                data.append(0x00)
            }
        }

        return data
    }

    /// A string representation of the APDU for debugging purposes.
    var description: String {
        "APDU(cla: \(cla.hexValue), ins: \(ins.hexValue), p1: \(p1.hexValue), p2: \(p2.hexValue), command: \(command?.hexEncodedString ?? "nil"), type: \(String(describing: type))"
    }
}
