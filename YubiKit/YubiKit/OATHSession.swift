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

    private init(connection: Connection) async throws {
        self.connection = connection
        try await connection.smartCardInterface.selectApplication(application: .OATH)
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        await internalConnection.session?.end(withConnectionStatus: .leaveOpen)
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection)
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
            print("End OATHSesssion and close connection")
        } else {
            print("End OATHSesssion")
        }
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await OATH sessionDidEnd")
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        print("OATH session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func calculateCode() async throws -> Code {
        print("Start OATH calculateCode()")
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        print("Finished calculateCode()")
        return Code(code: "\(Int.random(in: 1000...9999))")
    }
    
    public func calculateCodes() async throws -> [Code] {
        print("Start OATH calculateCodes")
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        print("Finished OATH calculateCodes\n")
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
    }
    
    public func calculateFailingCode() async throws -> String {
        _ = try await connection?.smartCardInterface.sendCommand(apdu: SmartCardInterface.APDU())
        throw "Something went wrong!"
    }

    deinit {
        print("deinit OATHSession")
    }
}
