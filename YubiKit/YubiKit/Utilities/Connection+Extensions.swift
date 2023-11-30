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
import OSLog

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
    
    public func send(apdu: APDU) async throws -> Data {
        Logger.connection.debug("send(): \(apdu)")
        return try await sendRecursive(apdu: apdu)
    }
    
    func selectApplication(_ application: Application) async throws -> Data {
        Logger.connection.debug("selectApplication(\(String(describing: application)))")
        do {
            return try await send(apdu: application.selectApplicationAPDU)
        } catch {
            guard let error = error as? ResponseError else { throw error }
            switch error.statusCode {
            case .insNotSupported, .missingFile:
                throw SessionError.missingApplication
            default:
                throw error
            }
        }
    }
    
    private func sendRecursive(apdu: APDU, data: Data = Data(), readMoreData: Bool = false) async throws -> Data {
        if data.count > 0 {
            Logger.connection.debug("sendRecursive() accumulated data: \(data))")
        }

        let response: Response
        
        let ins: UInt8
        guard let internalConnection = self as? InternalConnection else { fatalError() }
        let session = await internalConnection.session()
        if session as? OATHSession != nil {
            ins = 0xa5
        } else {
            ins = 0xc0
        }

        guard let internalConnection = self as? InternalConnection else { fatalError() }
        if readMoreData {
            let apdu =  APDU(cla: 0, ins: ins, p1: 0, p2: 0, command: nil, type: .short)
            response = try await internalConnection.send(apdu: apdu)
        } else {
            response = try await internalConnection.send(apdu: apdu)
        }
        
        guard response.statusCode == .ok || response.statusCode == .moreData else {
            Logger.connection.error("send() failed with statusCode: \(response.statusCode.rawValue.data.hexEncodedString)")
            throw ResponseError(statusCode: response.statusCode)
        }
        
        let newData = data + response.data
        if response.statusCode == .moreData {
            return try await sendRecursive(apdu: apdu, data: newData, readMoreData: true)
        } else {
            Logger.connection.debug("send() response: \(newData.hexEncodedString)")
            return newData
        }
    }
}
