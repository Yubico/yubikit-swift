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

struct Response: CustomStringConvertible, Sendable {

    init(rawData: Data) {
        if rawData.count > 2 {
            data = rawData.subdata(in: 0..<rawData.count - 2)
        } else {
            data = Data()
        }
        responseStatus = ResponseStatus(data: rawData.subdata(in: rawData.count - 2..<rawData.count))
    }

    internal init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        responseStatus = ResponseStatus(sw1: sw1, sw2: sw2)
    }

    /// The data returned in the response.
    /// >Note: The data does not contain the response code. It is stored in the `ResponseStatus`.
    let data: Data

    /// Status code of the response
    let responseStatus: ResponseStatus
    var description: String {
        "<Response: \(responseStatus.status) \(responseStatus.rawStatus.data.hexEncodedString), length: \(data.count)>"
    }
}

public struct ResponseStatus: Equatable, Sendable {
    public enum StatusCode: UInt16, CustomStringConvertible, Sendable {
        case ok = 0x9000
        case noInputData = 0x6285
        case verifyFailNoRetry = 0x63C0
        case memoryError = 0x6581
        case wrongLength = 0x6700
        case securityConditionNotSatisfied = 0x6982
        case authMethodBlocked = 0x6983
        case dataInvalid = 0x6984
        case conditionsNotSatisfied = 0x6985
        case commandNotAllowed = 0x6986
        case incorrectParameters = 0x6A80
        case referencedDataNotFound = 0x6a88
        case fileNotFound = 0x6A82
        case noSpace = 0x6A84
        case wrongParametersP1P2 = 0x6B00
        case invalidInstruction = 0x6D00
        case claNotSupported = 0x6E00
        case commandAborted = 0x6F00
        case unknown = 0x0000

        public var description: String { "0x\(self.rawValue.bigEndian.data.hexEncodedString)" }
    }

    public let status: StatusCode
    public let rawStatus: UInt16
    public var sw1: UInt8 { UInt8((rawStatus & 0xff00) >> 8) }
    public var sw2: UInt8 { UInt8(rawStatus & 0xff00) }

    internal init(sw1: UInt8, sw2: UInt8) {
        rawStatus = UInt16(sw1) << 8 + UInt16(sw2)
        status = StatusCode(rawValue: rawStatus) ?? .unknown
    }

    internal init(data: Data) {
        let value = data.uint16.bigEndian
        let sw1 = UInt8((value & 0xff00) >> 8)
        let sw2 = UInt8(value & 0x00ff)
        self.init(sw1: sw1, sw2: sw2)
    }
}
