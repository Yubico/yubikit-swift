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

public final class OATHSession: Session, InternalSession {
    
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) {
        self.connection = connection
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        let internalConnection = connection as! InternalConnection
        if let session = internalConnection.session as? OATHSession {
            if let nfcConnection = session.connection as? NFCConnection, let connection = connection as? NFCConnection, nfcConnection === connection {
                return session
            }
            if let lightningConnection = session.connection as? LightningConnection, let connection = connection as? LightningConnection, lightningConnection === connection {
                return session
            }
            fatalError()
        }
        internalConnection.session?.end(result: nil, closingConnection: false)
        let session = OATHSession(connection: connection)
        return session
    }
    
    public func end(result: Result<String, Error>?, closingConnection: Bool) {
        endingResult = result
        sessionEnded = true
        if closingConnection {
            connection?.close(nil)
        }
        var internalConnection = self.internalConnection
        internalConnection.session = nil
        connection = nil
        print("End OATH session\(closingConnection ? " and close connection" : "")")
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await OATH sessionDidEnd")
        while !sessionEnded {
            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        print("OATH session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func calculateCode() async throws -> Code {
        await Task.sleep(1_000_000_000 * UInt64(0.5))
        return Code(code: "\(Int.random(in: 1000...9999))")
    }
    
    public func calculateCodes() async throws -> [Code] {
        print("Execute OATH calculateCodes")
        await Task.sleep(1_000_000_000 * UInt64(1.0))
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
    }
    
    public func calculateFailingCode() async throws -> String {
        await Task.sleep(1_000_000_000 * UInt64(1.0))
        throw "Something went wrong!"
    }

    deinit {
        print("deinit OATHSession")
    }
}
