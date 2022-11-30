//
//  APDU.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-12-07.
//

import Foundation

/*
@param cla
   The instruction class.
@param ins
   The instruction number.
@param p1
   The first instruction paramater byte.
@param p2
   The second instruction paramater byte.
@param data
   The command data.
@param type
   The type of the APDU, short or extended.
*/

public struct APDU {
    
    public enum ApduType {
        case short
        case extended
    }
    
    public let cla: UInt8
    public let ins: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: Data?
    public let type: ApduType
    
    var apduData: Data {
        var apduData = Data()
        apduData.append(cla)
        apduData.append(ins)
        apduData.append(p1)
        apduData.append(p2)

        switch type {
        case .short:
            if let data, data.count > 0 {
                guard data.count < UInt8.max else { fatalError() }
                let length = UInt8(data.count)
                apduData.append(length)
                apduData.append(data)
            }
        case .extended:
            if let data, data.count > 0 {
                let lengthHigh: UInt8 = UInt8(data.count / 256)
                let lengthLow: UInt8 = UInt8(data.count % 256)
                apduData.append(0x00)
                apduData.append(lengthHigh)
                apduData.append(lengthLow)
                apduData.append(data)
            } else {
                apduData.append(0x00)
                apduData.append(0x00)
                apduData.append(0x00)
            }
        }

        return apduData
    }
    
}
