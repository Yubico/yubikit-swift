//
//  ManagementSession.swift
//  
//
//  Created by Jens Utbult on 2021-11-25.
//

import Foundation
import CryptoTokenKit

public enum ManagementSessionError: Error {
    case noConnection
}

public final class ManagementSession: Session, InternalSession {
    
    public var version: Version
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) async throws {
        let result = try await connection.selectApplication(application: .management)
        guard let version = Version(withManagementResult: result) else { throw "Failed to parse version string from response." }
        self.version = version
        self.connection = connection
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
            await connection?.close(result: result)
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
//        _ = try await connection?.send(apdu: SmartCardInterface.APDU())
        print("ManagementSession session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func getDeviceInfo() async throws -> DeviceInfo {
        guard let connection else { throw ManagementSessionError.noConnection }
        let apdu = APDU(cla: 0, ins: 0x1d, p1: 0, p2: 0)
        let data: Data = try await connection.send(apdu: apdu)
        return try DeviceInfo(withData: data, fallbackVersion: version)
    }

    deinit {
        print("deinit ManagementSession")
    }
}

extension Version {
    init?(withManagementResult data: Data) {
        guard let resultString = String(bytes: data.bytes, encoding: .ascii) else { return nil }
        guard let versions = resultString.components(separatedBy: " ").last?.components(separatedBy: "."), versions.count == 3 else {
            return nil
        }
        guard let major = UInt8(versions[0]), let minor = UInt8(versions[1]), let micro = UInt8(versions[2]) else {
            return nil
        }
        self.major = major
        self.minor = minor
        self.micro = micro
    }
}
