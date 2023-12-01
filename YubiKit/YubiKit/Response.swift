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

internal struct Response: CustomStringConvertible {

    internal init(rawData: Data) {
        if rawData.count > 2 {
            data = rawData.subdata(in: 0..<rawData.count - 2)
        } else {
            data = Data()
        }
        statusCode = ResponseStatusCode(data: rawData.subdata(in: rawData.count - 2..<rawData.count))!
    }
    
    internal init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        statusCode = ResponseStatusCode(sw1: sw1, sw2: sw2)!
    }
    
    /// The data returned in the response.
    public let data: Data
    
    /// Status code of the response
    internal let statusCode: ResponseStatusCode
    public var description: String {
        return "<Result: \(statusCode) (\(statusCode.rawValue.data.hexEncodedString), length: \(data.count)>"
    }
}


extension ResponseStatusCode {
    
    internal init?(sw1: UInt8, sw2: UInt8) {
        if sw1 == 0x61 {
            self.init(rawValue: UInt16(sw1) << 8 + UInt16(0))
        } else {
            self.init(rawValue: UInt16(sw1) << 8 + UInt16(sw2))
        }
    }
    
    internal init?(data: Data) {
        let value = data.uint16.bigEndian
        if UInt8(value >> 8) == 0x61 {
            self.init(rawValue: UInt16(0x61) << 8 + UInt16(0))
        } else {
            self.init(rawValue: value)
        }
    }
    
    public var sw1: UInt8 {
        UInt8((self.rawValue & 0xff00) >> 8)
    }
    
    public var sw2: UInt8 {
        UInt8(self.rawValue & 0x00ff)
    }
}
