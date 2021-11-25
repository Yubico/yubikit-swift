//
//  ManagementSession.swift
//  
//
//  Created by Jens Utbult on 2021-11-25.
//

import Foundation


public final class ManagementSession: Session, InternalSession {
    
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) {
        self.connection = connection
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> ManagementSession {
        let internalConnection = connection as! InternalConnection
        if let session = internalConnection.session as? ManagementSession {
            if let nfcConnection = session.connection as? NFCConnection, let connection = connection as? NFCConnection, nfcConnection === connection {
                return session
            }
            if let lightningConnection = session.connection as? LightningConnection, let connection = connection as? LightningConnection, lightningConnection === connection {
                return session
            }
            fatalError()
        }
        internalConnection.session?.end(result: nil, closingConnection: false)
        let session = ManagementSession(connection: connection)
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
        print("End ManagementSession session\(closingConnection ? " and close connection" : "")")
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await ManagementSession sessionDidEnd")
        while !sessionEnded {
            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        print("ManagementSession session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func getKeyVersion() async throws -> String {
        await Task.sleep(1_000_000_000 * UInt64(0.5))
        return "3.14"
    }

    deinit {
        print("deinit ManagementSession")
    }
}
