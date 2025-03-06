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
import CryptoTokenKit
import OSLog


public final actor SecurityDomainSession: Session, InternalSession {
    
    private weak var _connection: Connection?
    internal func connection() async -> Connection? {
        return _connection
    }
    internal func setConnection(_ connection: Connection?) async {
        _connection = connection
    }

    private init(connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws {
        let result = try await connection.selectApplication(.securityDomain)
        self._connection = connection
        let internalConnection = await self.internalConnection()
        if let scpKeyParams {
            let processor = try await SCPProcessor(connection: connection, keyParams: scpKeyParams)
            await internalConnection?.setProcessor(processor)
        }
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws -> SecurityDomainSession {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        let internalConnection = connection as? InternalConnection
        let currentSession = await internalConnection?.session()
        await currentSession?.end()
        let session = try await SecurityDomainSession(connection: connection, scpKeyParams: scpKeyParams)
        return session
    }
    
    public func end() async {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(nil)
        await setConnection(nil)
    }
    
    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        return true
    }
    
    public func getData(tag: UInt16, data: Data?) async throws -> Data {
        guard let connection = _connection else { throw SessionError.noConnection }
        return try await connection.send(apdu: APDU(cla: 0x00, ins: 0xCA, p1: UInt8(tag >> 8) , p2: UInt8(tag & 0xff), command: data))
    }
    
    public func getCertificateBundle(scpKeyRef: SCPKeyRef) async throws -> [SecCertificate] {
        do {
            let result = try await getData(tag: 0xBF21, data: TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: scpKeyRef.data).data).data)
            guard let rawCerts = TKBERTLVRecord.sequenceOfRecords(from: result) else { fatalError() }
            let certs = rawCerts.map { SecCertificateCreateWithData(nil, $0.data as CFData) }.compactMap { $0 }
            guard certs.count == rawCerts.count else { fatalError() }
            return certs
        } catch {
            if let reponseError = error as? ResponseError, reponseError.responseStatus.status == .referencedDataNotFound {
                return []
            } else {
                throw error
            }
        }
    }
    
    deinit {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
    }
}
