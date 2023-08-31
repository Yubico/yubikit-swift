//
//  ManagementSession.swift
//  
//
//  Created by Jens Utbult on 2021-11-25.
//

import Foundation
import CryptoTokenKit

enum ManagementSessionError: Error {
    case applicationNotSupported
    case unexpectedYubikeyConfigState
    case versionParseError
}

public final class ManagementSession: Session, InternalSession {
    
    public var version: Version
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) async throws {
        let result = try await connection.selectApplication(application: .management)
        guard let version = Version(withManagementResult: result) else { throw ManagementSessionError.versionParseError }
        self.version = version
        self.connection = connection
        var internalConnection = connection as! InternalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> ManagementSession {
        // Close active session if there is one
        let internalConnection = connection as? InternalConnection
        internalConnection?.session?.end()
        // Create a new ManagementSession
        let session = try await ManagementSession(connection: connection)
        return session
    }
    
    public func end() {
        var internalConnection = connection as? InternalConnection
        internalConnection?.session = nil
        self.connection = nil
    }
    
    public func sessionDidEnd() async -> Error? {
        print("await ManagementSession sessionDidEnd")
//        _ = try await connection?.send(apdu: SmartCardInterface.APDU())
        print("ManagementSession session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func getDeviceInfo() async throws -> DeviceInfo {
        guard let connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: 0x1d, p1: 0, p2: 0)
        let data: Data = try await connection.send(apdu: apdu)
        return try DeviceInfo(withData: data, fallbackVersion: version)
    }
    
    public func isApplicationSupported(_ application: ApplicationType, overTransport transport: DeviceTransport) async throws -> Bool {
        let deviceInfo = try await getDeviceInfo()
        return deviceInfo.config.isApplicationEnabled(application, overTransport: transport)
    }
    
    public func setEnabled(_ enabled: Bool, application: ApplicationType, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        guard let connection else { throw SessionError.noConnection }
        let deviceInfo = try await getDeviceInfo()
        guard enabled != deviceInfo.config.isApplicationEnabled(application, overTransport: transport) else { return }
        guard deviceInfo.isApplicationSupported(application, overTransport: transport) else {
            throw ManagementSessionError.applicationNotSupported
        }
        let config = deviceInfo.config.deviceConfigWithEnabled(enabled, application: application, overTransport: transport)
        
        guard let newConfigValue = config?.enabledCapabilities[transport] else {
            throw ManagementSessionError.unexpectedYubikeyConfigState
        }
        
        var data = Data()
        data.append(UInt8(newConfigValue & 0xff00 >> 8))
        data.append(UInt8(newConfigValue & 0xff))
        
        if reboot {
            data.append([0x0c, 0x00], count: 2)
        }
        let tlv = TKBERTLVRecord(tag: transport == .nfc ? deviceInfo.isNFCEnabledTag : deviceInfo.isUSBEnabledTag , value: data)
        
        var command = Data()
        command.append(tlv.data.count.data.uint8)
        command.append(tlv.data)
        
        let apdu = APDU(cla: 0, ins: 0x1c, p1: 0, p2: 0, command: command)
        let _: Data = try await connection.send(apdu: apdu)
    }
    
    public func disableApplication(_ application: ApplicationType, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        try await setEnabled(false, application: application, overTransport: transport, reboot: reboot)
    }
    
    public func enableApplication(_ application: ApplicationType, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        try await setEnabled(true, application: application, overTransport: transport, reboot: reboot)
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
