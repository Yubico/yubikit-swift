//
//  Connection+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-08.
//

import Foundation

public struct ResponseError: Error {
    let statusCode: Response.StatusCode
}

extension Connection {

    func send(apdu: APDU, isOATH: Bool = false) async throws -> Data {
        return try await sendRecursive(apdu: apdu, isOATH: isOATH)
    }
    
    private func sendRecursive(apdu: APDU, isOATH: Bool = false, data: Data = Data(), readMoreData: Bool = false) async throws -> Data {
        let response: Response
        if readMoreData {
            let apdu =  APDU(cla: 0, ins: isOATH ? 0xa5 : 0xc0, p1: 0, p2: 0, data: nil, type: .short)
            response = try await send(apdu: apdu)
        } else {
            response = try await send(apdu: apdu)
        }
        
        guard response.statusCode == .ok || response.statusCode == .moreData else {
            throw ResponseError(statusCode: response.statusCode)
        }
        
        let newData = data + response.data
        if response.statusCode == .moreData {
            return try await sendRecursive(apdu: apdu, isOATH: isOATH, data: newData, readMoreData: true)
        } else {
            return newData
        }
    }
}
