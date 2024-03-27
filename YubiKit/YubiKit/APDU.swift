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
public struct APDU: CustomStringConvertible {
    
    public enum ApduType {
        case short
        case extended
    }
    
    private struct ExplicitAPDU {
        let cla: UInt8
        let ins: UInt8
        let p1: UInt8
        let p2: UInt8
        let command: Data?
        let type: ApduType
    }
    
    private enum APDUStorage {
        case explicit(ExplicitAPDU)
        case rawData(Data)
    }
    
    private let storage: APDUStorage
    
    /// Creates an APDU struct.
    /// - Parameters:
    ///   - cla: The instruction class.
    ///   - ins: The instruction code.
    ///   - p1: The first instruction paramater byte.
    ///   - p2: The second instruction paramater byte.
    ///   - command: The command data.
    ///   - type: The type of the APDU, short or extended.
    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, command: Data? = nil, type: ApduType = .short) {
        self.storage = .explicit(ExplicitAPDU(cla: cla, ins: ins, p1: p1, p2: p2, command: command, type: type))
    }
    
    /// Creates an APDU struct.
    /// - Parameters:
    ///   - data: The raw data to send to they YubiKey.
    public init(data: Data) {
        self.storage = .rawData(data)
    }
    
    public var data: Data {
        switch storage {
        case .explicit(let apdu):
            var data = Data()
            data.append(apdu.cla)
            data.append(apdu.ins)
            data.append(apdu.p1)
            data.append(apdu.p2)
            switch apdu.type {
            case .short:
                if let command = apdu.command, command.count > 0 {
                    guard command.count < UInt8.max else { fatalError() }
                    let length = UInt8(command.count)
                    data.append(length)
                    data.append(command)
                }
            case .extended:
                if let command = apdu.command, command.count > 0 {
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
        case .rawData(let data):
            return data
        }
    }
    
    public var description: String {
        switch storage {
        case .explicit(let apdu):
            return "APDU(cla: \(apdu.cla.hexValue), ins: \(apdu.ins.hexValue), p1: \(apdu.p1.hexValue), p2: \(apdu.p2.hexValue), command: \(apdu.command?.hexEncodedString ?? "nil"), type: \(String(describing: apdu.type))"
        case .rawData(let data):
            return "APDU(data: \(data.hexEncodedString))"
        }
    }
}
