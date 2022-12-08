//
//  Response.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-07.
//

import Foundation

public struct Response: CustomStringConvertible {

    internal init(rawData: Data) {
        if rawData.count > 2 {
            data = rawData.subdata(in: 0..<rawData.count - 2)
        } else {
            data = Data()
        }
        statusCode = StatusCode(rawValue: rawData.subdata(in: rawData.count - 2..<rawData.count).uint16)!
    }
    
    internal init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        print(UInt16(sw1) << 8 + UInt16(sw2))
        statusCode = StatusCode(rawValue: UInt16(sw1) << 8 + UInt16(sw2))!
    }
    
    public let data: Data
    public let statusCode: StatusCode
    public var description: String {
        return "<Result: \(statusCode) (\(statusCode.rawValue.data.hexEncodedString), length: \(data.count)>"
    }

    public enum StatusCode: UInt16 {
        case ok = 0x9000
        case fido2TouchRequired = 0x9100
        case conditionNotSatisfied = 0x6985
        
        case authenticationRequired = 0x6982
        case codeDataInvalid = 0x6984
        case wrongLength = 0x6700
        case wrongData = 0x6A80
        case insNotSupported = 0x6D00
        case claNotSupported = 0x6E00
        case commandAborted = 0x6F00
        case missingFile = 0x6A82

        case moreData = 0x61 // 0x61XX
    }
}
