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


enum Application {
    case oath
    case management
    case piv
    case securityDomain
    
    var selectApplicationAPDU: APDU {
        let data: Data
        switch self {
        case .oath:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        case .management:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        case .piv:
            data = Data([0xA0, 0x00, 0x00, 0x03, 0x08])
        case .securityDomain:
            data = Data([0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00])
        }
        
        return APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: data, type: .short)
    }
}

extension Connection {
    
    @discardableResult
    public func send(apdu: APDU) async throws -> Data {
        let internalConnection = self as! InternalConnection
        if let processor = await internalConnection.getProcessor() {
            print("👾 send data using processor")
            return try await processor.send(apdu: apdu, using: self)
        } else {
            print("👾 send data without processor")
            return try await sendRecursive(apdu: apdu)
        }
    }
    
    private func send(apdu: APDU, useProcessor: Bool = true) async throws -> Data {
        let internalConnection = self as! InternalConnection
        if useProcessor, let processor = await internalConnection.getProcessor() {
            print("👾 send data using processor")
            return try await processor.send(apdu: apdu, using: self)
        } else {
            print("👾 send data without processor")
            return try await sendRecursive(apdu: apdu)
        }
    }
    
    @discardableResult
    internal func selectApplication(_ application: Application) async throws -> Data {
        Logger.connection.debug("Connection+Extension, \(#function): \(String(describing: application))")
        let internalConnection = self as! InternalConnection
        await internalConnection.setProcessor(nil)
        do {
            return try await send(apdu: application.selectApplicationAPDU)
        } catch {
            guard let error = error as? ResponseError else { throw error }
            switch error.responseStatus.status {
            case .invalidInstruction, .fileNotFound:
                throw SessionError.missingApplication
            default:
                throw error
            }
        }
    }
    
    internal func sendRecursive(apdu: APDU, data: Data = Data(), readMoreData: Bool = false) async throws -> Data {
        Logger.connection.debug("Connection+Extension, \(#function): accumulated data: \(data)")

        let responseData: Data
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
            responseData = try await self.send(data: apdu.data)
        } else {
            responseData = try await self.send(data: apdu.data)
        }
        response = Response(rawData: responseData)
        
        guard response.responseStatus.status == .ok || response.responseStatus.sw1 == 0x61 else {
            Logger.connection.error("Connection+Extension, \(#function): failed with statusCode: \(response.responseStatus.status)")
            throw ResponseError(responseStatus: response.responseStatus)
        }
        
        let newData = data + response.data
        if response.responseStatus.sw1 == 0x61 {
            return try await sendRecursive(apdu: apdu, data: newData, readMoreData: true)
        } else {
            Logger.connection.debug("Connection+Extension, \(#function): response: \(newData.hexEncodedString)")
            return newData
        }
    }
}
