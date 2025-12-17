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

public struct Response: Sendable {

    init(rawData: Data) {
        if rawData.count > 2 {
            data = rawData.subdata(in: 0..<rawData.count - 2)
        } else {
            data = Data()
        }
        responseStatus = Response.Status(data: rawData.subdata(in: rawData.count - 2..<rawData.count))
    }

    init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        responseStatus = Response.Status(sw1: sw1, sw2: sw2)
    }

    /// The data returned in the response.
    /// > Note: The data does not contain the response code. It is stored in the ``Response/Status``.
    let data: Data

    /// Status code of the response
    public let responseStatus: Response.Status

    /// Convenience property to access the status code directly
    public var status: Response.Status.Code {
        responseStatus.status
    }

    /// Convenience property to access the raw status value directly
    public var rawStatus: UInt16 {
        responseStatus.rawStatus
    }

    // NEXTMAJOR: Remove these deprecated properties
    /// Convenience property to access sw1 directly
    @available(*, deprecated, message: "Use responseStatus.sw1 instead")
    public var sw1: UInt8 {
        responseStatus.sw1
    }

    /// Convenience property to access sw2 directly
    @available(*, deprecated, message: "Use responseStatus.sw2 instead")
    public var sw2: UInt8 {
        responseStatus.sw2
    }
}

extension Response {
    public struct Status: Equatable, Sendable {
        public enum Code: UInt16, CustomStringConvertible, Sendable {
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

        public let status: Code
        public let sw1: UInt8
        public let sw2: UInt8

        public var rawStatus: UInt16 {
            (UInt16(sw1) << 8) | UInt16(sw2)
        }

        internal init(sw1: UInt8, sw2: UInt8) {
            self.sw1 = sw1
            self.sw2 = sw2
            let rawValue = (UInt16(sw1) << 8) | UInt16(sw2)
            status = Code(rawValue: rawValue) ?? .unknown
        }

        internal init(data: Data) {
            let value = data.uint16.bigEndian
            self.init(sw1: UInt8((value & 0xff00) >> 8), sw2: UInt8(value & 0x00ff))
        }
    }
}

// NEXTMAJOR: Remove these typealiases
@available(*, deprecated, renamed: "Response.Status")
public typealias ResponseStatus = Response.Status

extension Response.Status {
    @available(*, deprecated, renamed: "Response.Status.Code")
    public typealias StatusCode = Code
}
