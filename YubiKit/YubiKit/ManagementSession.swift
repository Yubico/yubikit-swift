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
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        await internalConnection.session?.end(withConnectionStatus: .leaveOpen)
        // Create a new ManagementSession
        let session = try await ManagementSession(connection: connection)
        return session
    }
    
    public func end(withConnectionStatus status: ConnectionStatus = .leaveOpen) async {
        switch status {
        case .close(let result):
            endingResult = result
            await connection?.close(result)
        default: break
        }
        sessionEnded = true
        var internalConnection = self.internalConnection
        internalConnection.session = nil
        connection = nil
        if case .leaveOpen = status {
            print("End ManagementSesssion and close connection")
        } else {
            print("End ManagementSesssion")
        }
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
