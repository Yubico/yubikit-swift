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

public enum ManagementSessionError: Error {
    /// Application is not supported on this YubiKey.
    case applicationNotSupported
    /// Unexpected configuration state.
    case unexpectedYubikeyConfigState
    /// Unexpected data returned by YubiKey.
    case unexpectedData
    /// YubiKey did not return any data.
    case missingData
}

/// An interface to the Management application on the YubiKey.
///
/// Use the Management application to get information and configure a YubiKey.
/// Read more about the Management application on the
/// [Yubico developer website](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
public final actor ManagementSession: Session, InternalSession {
    
    var _connection: Connection?
    
    func connection() async -> Connection? {
        return _connection
    }
    
    func setConnection(_ connection: Connection?) async {
        _connection = connection
    }
    
    
    public nonisolated let version: Version
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) async throws {
        let result = try await connection.selectApplication(application: .management)
        guard let version = Version(withManagementResult: result) else { throw ManagementSessionError.unexpectedData }
        self.version = version
        self.connection = connection
        let internalConnection = await self.internalConnection()
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection) async throws -> ManagementSession {
        // Close active session if there is one
        let internalConnection = connection as? InternalConnection
        let currentSession = await internalConnection?.session()
        await currentSession?.end()
        // Create a new ManagementSession
        let session = try await ManagementSession(connection: connection)
        return session
    }
    
    public func end() async {
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(nil)
        self.connection = nil
    }
    
    public func sessionDidEnd() async -> Error? {
        print("await ManagementSession sessionDidEnd")
//        _ = try await connection?.send(apdu: SmartCardInterface.APDU())
        print("ManagementSession session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    /// Returns the DeviceInfo for the connected YubiKey.
    public func getDeviceInfo() async throws -> DeviceInfo {
        guard let connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: 0x1d, p1: 0, p2: 0)
        let data = try await connection.send(apdu: apdu)
        return try DeviceInfo(withData: data, fallbackVersion: version)
    }
    
    /// Check whether an application is supported over the specified transport.
    public func isApplicationSupported(_ application: ApplicationType, overTransport transport: DeviceTransport) async throws -> Bool {
        let deviceInfo = try await getDeviceInfo()
        return deviceInfo.isApplicationSupported(application, overTransport: transport)
    }
    
    /// Check whether an application is enabled over the specified transport.
    public func isApplicationEnabled(_ application: ApplicationType, overTransport transport: DeviceTransport) async throws -> Bool {
        let deviceInfo = try await getDeviceInfo()
        return deviceInfo.config.isApplicationEnabled(application, overTransport: transport)
    }
    
    /// Enable or disable an application over the specified transport.
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
        try await connection.send(apdu: apdu)
    }
    
    /// Disable an application over the specified transport.
    public func disableApplication(_ application: ApplicationType, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        try await setEnabled(false, application: application, overTransport: transport, reboot: reboot)
    }
    
    /// Enable an application over the specified transport.
    public func enableApplication(_ application: ApplicationType, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        try await setEnabled(true, application: application, overTransport: transport, reboot: reboot)
    }
    
    deinit {
        print("deinit ManagementSession")
    }
}

extension Version {
    internal init?(withManagementResult data: Data) {
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
