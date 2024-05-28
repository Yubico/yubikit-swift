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

public enum ManagementSessionError: Error {
    /// Application is not supported on this YubiKey.
    case applicationNotSupported
    /// Unexpected configuration state.
    case unexpectedYubikeyConfigState
    /// Unexpected data returned by YubiKey.
    case unexpectedData
    /// YubiKey did not return any data.
    case missingData
    /// Device configuration too large
    case configTooLarge
}

/// An interface to the Management application on the YubiKey.
///
/// Use the Management application to get information and configure a YubiKey.
/// Read more about the Management application on the
/// [Yubico developer website](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
public final actor ManagementSession: Session, InternalSession {
    
    private weak var _connection: Connection?
    internal func connection() async -> Connection? {
        return _connection
    }
    internal func setConnection(_ connection: Connection?) async {
        _connection = connection
    }
    
    public nonisolated let version: Version

    private init(connection: Connection) async throws {
        let result = try await connection.selectApplication(.management)
        guard let version = Version(withManagementResult: result) else { throw ManagementSessionError.unexpectedData }
        self.version = version
        self._connection = connection
        let internalConnection = await self.internalConnection()
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection) async throws -> ManagementSession {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        // Close active session if there is one
        let internalConnection = connection as? InternalConnection
        let currentSession = await internalConnection?.session()
        await currentSession?.end()
        // Create a new ManagementSession
        let session = try await ManagementSession(connection: connection)
        return session
    }
    
    public func end() async {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(nil)
        await setConnection(nil)
    }
    
    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        return feature.isSupported(by: version)
    }

    /// Returns the DeviceInfo for the connected YubiKey.
    public func getDeviceInfo() async throws -> DeviceInfo {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(ManagementFeature.deviceInfo) else { throw SessionError.notSupported }
        guard let connection = _connection else { throw SessionError.noConnection }
        
        var page: UInt8 = 0
        var hasMoreData = true
        var result = [TKTLVTag : Data]()
        while hasMoreData {
            let apdu = APDU(cla: 0, ins: 0x1d, p1: page, p2: 0)
            let data = try await connection.send(apdu: apdu)
            guard let count = data.bytes.first, count > 0 else { throw ManagementSessionError.missingData }
            guard let tlvs = TKBERTLVRecord.dictionaryOfData(from: data.subdata(in: 1..<data.count)) else { throw ManagementSessionError.unexpectedData }
            Logger.management.debug("\(String(describing: self).lastComponent), \(#function): page: \(page), data: \(data.hexEncodedString)")
            result.merge(tlvs) { (_, new) in new }
            hasMoreData = tlvs[0x10] != nil
            page += 1
        }
        
        return try DeviceInfo(withTlvs: result, fallbackVersion: version)
    }
    
    public func updateDeviceConfig(_ config: DeviceConfig, reboot: Bool, lockCode: Data? = nil, newLockCode: Data? = nil) async throws {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(ManagementFeature.deviceConfig) else { throw SessionError.notSupported }
        guard let connection = _connection else { throw SessionError.noConnection }
        let data = try config.data(reboot: reboot, lockCode: lockCode, newLockCode: newLockCode)
        let apdu = APDU(cla: 0, ins: 0x1c, p1: 0, p2: 0, command: data)
        try await connection.send(apdu: apdu)
    }
    
    /// Check whether an application is supported over the specified transport.
    public func isApplicationSupported(_ application: Capability, overTransport transport: DeviceTransport) async throws -> Bool {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        let deviceInfo = try await getDeviceInfo()
        return deviceInfo.isApplicationSupported(application, overTransport: transport)
    }
    
    /// Check whether an application is enabled over the specified transport.
    public func isApplicationEnabled(_ application: Capability, overTransport transport: DeviceTransport) async throws -> Bool {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        let deviceInfo = try await getDeviceInfo()
        return deviceInfo.config.isApplicationEnabled(application, overTransport: transport)
    }
    
    /// Enable or disable an application over the specified transport.
    public func setEnabled(_ enabled: Bool, application: Capability, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function): \(enabled), application: \(String(describing: application)), overTransport: \(String(describing: transport)), reboot: \(reboot)")
        let deviceInfo = try await getDeviceInfo()
        guard enabled != deviceInfo.config.isApplicationEnabled(application, overTransport: transport) else { return }
        guard deviceInfo.isApplicationSupported(application, overTransport: transport) else {
            throw ManagementSessionError.applicationNotSupported
        }
        guard let config = deviceInfo.config.deviceConfig(enabling: enabled, application: application, overTransport: transport) else { return }
        
        guard config.enabledCapabilities[transport] != nil else {
            throw ManagementSessionError.unexpectedYubikeyConfigState
        }
        
        try await updateDeviceConfig(config, reboot: reboot)
    }
    
    /// Disable an application over the specified transport.
    public func disableApplication(_ application: Capability, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: application)), overTransport: \(String(describing: transport)), reboot: \(reboot)")
        try await setEnabled(false, application: application, overTransport: transport, reboot: reboot)
    }
    
    /// Enable an application over the specified transport.
    public func enableApplication(_ application: Capability, overTransport transport: DeviceTransport, reboot: Bool = false) async throws {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: application)), overTransport: \(String(describing: transport)), reboot: \(reboot)")
        try await setEnabled(true, application: application, overTransport: transport, reboot: reboot)
    }
    
    deinit {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
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
