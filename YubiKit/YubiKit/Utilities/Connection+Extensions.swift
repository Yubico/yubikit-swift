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

enum Application {
    case oath
    case management
    
    var selectApplicationAPDU: APDU {
        let data: Data
        switch self {
        case .oath:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        case .management:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        }
        return APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: data, type: .short)
    }
}

extension Connection {
    
    func selectApplication(application: Application) async throws -> Data {
        let response: Response = try await send(apdu: application.selectApplicationAPDU)
        switch response.statusCode {
        case .ok:
            return response.data
        case .insNotSupported, .missingFile:
            throw SessionError.missingApplication
        default:
            throw SessionError.unexpectedStatusCode
        }
    }
    
    func send(apdu: APDU) async throws -> Data {
        return try await sendRecursive(apdu: apdu)
    }
    
    private func sendRecursive(apdu: APDU, data: Data = Data(), readMoreData: Bool = false) async throws -> Data {
        let response: Response
        
        let ins: UInt8
        guard let internalConnection = self as? InternalConnection else { fatalError() }
        let session = await internalConnection.session()
        if session as? OATHSession != nil {
            ins = 0xa5
        } else {
            ins = 0xc0
        }

        if readMoreData {
            let apdu =  APDU(cla: 0, ins: ins, p1: 0, p2: 0, command: nil, type: .short)
            response = try await send(apdu: apdu)
        } else {
            response = try await send(apdu: apdu)
        }
        
        guard response.statusCode == .ok || response.statusCode == .moreData else {
            throw ResponseError(statusCode: response.statusCode)
        }
        
        let newData = data + response.data
        if response.statusCode == .moreData {
            return try await sendRecursive(apdu: apdu, data: newData, readMoreData: true)
        } else {
            return newData
        }
    }
}
