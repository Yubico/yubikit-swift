//
//  OATHSession.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public struct Code: Identifiable {
    public let id = UUID()
    public let code: String
}

public struct OATHSession: Session, InternalSession {
    public func end(_: Result<Error, String>?, closingConnection: Bool = false) {
        print("end OATHSession")
    }
    
    private static var session: OATHSession?
    internal var connection: Connection
    let endingSemaphore = DispatchSemaphore(value: 1)

    private init(connection: Connection) {
        self.connection = connection
        Self.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        if let session = Self.session {
            if let nfcConnection = session.connection as? NFCConnection, let connection = connection as? NFCConnection, nfcConnection === connection {
                return session
            }
            if let lightningConnection = session.connection as? LightningConnection, let connection = connection as? LightningConnection, lightningConnection === connection {
                return session
            }
        }
        session?.connection.close(nil)
        let session = OATHSession(connection: connection)
        OATHSession.session = session
        return session
    }
    
    public func end(_: Result<Error, String>?, closeConnection: Bool = false) {
        endingSemaphore.signal()
        if closeConnection {
            connection.close(nil)
        }
        Self.session = nil
        print("end")
    }
    
    public func sessionDidEnd() async throws -> Error? {
        endingSemaphore.wait()
        print("sessionDidEnd")
        return nil
    }

    public func calculateCode() async throws -> Code {
        await Task.sleep(1_000_000_000 * UInt64(0.5))
        return Code(code: "\(Int.random(in: 1000...9999))")
    }
    
    public func calculateCodes() async throws -> [Code] {
        await Task.sleep(1_000_000_000 * UInt64(0.5))
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
    }
    
    public func calculateFailingCode() async throws -> String {
        await Task.sleep(1_000_000_000 * UInt64(0.5))
        throw "Something went wrong!"
    }

}
