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

    private init(connection: Connection) async throws {
        self.connection = connection
        try await connection.smartCardInterface.selectApplication(application: .Management)
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> ManagementSession {
        let internalConnection = connection as! InternalConnection
        // Get the current session for this connection and check if it's a ManagementSession, if so return it
        if let session = internalConnection.session as? ManagementSession {
            if let nfcConnection = session.connection as? NFCConnection, let connection = connection as? NFCConnection, nfcConnection === connection {
                return session
            }
            if let lightningConnection = session.connection as? LightningConnection, let connection = connection as? LightningConnection, lightningConnection === connection {
                return session
            }
            fatalError()
        }
        // Close active session if there is one
        await internalConnection.session?.end(result: nil, closingConnection: false)
        // Create a new ManagementSession
        let session = try await ManagementSession(connection: connection)
        return session
    }
    
    public func end(result: Result<String, Error>?, closingConnection: Bool) async {
        endingResult = result
        sessionEnded = true
        if closingConnection {
            await connection?.close(nil)
        }
        var internalConnection = self.internalConnection
        internalConnection.session = nil
        connection = nil
        print("End ManagementSession session\(closingConnection ? " and close connection" : "")")
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await ManagementSession sessionDidEnd")
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        print("ManagementSession session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func getKeyVersion() async throws -> String {
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        return "3.14"
    }

    deinit {
        print("deinit ManagementSession")
    }
}
