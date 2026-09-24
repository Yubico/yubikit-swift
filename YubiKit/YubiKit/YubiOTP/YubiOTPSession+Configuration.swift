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
import Logging

extension YubiOTP.Session {

    /// Writes a configuration to a slot and replaces the configuration that was there.
    ///
    /// - Parameters:
    ///   - configuration: The slot configuration to write.
    ///   - slot: The slot to program.
    ///   - accessCode: Whether to keep, replace, or remove the access code of the slot.
    ///   - currentAccessCode: The current access code of the slot, if the slot is protected.
    public func putConfiguration(
        _ configuration: YubiOTP.SlotConfiguration,
        in slot: YubiOTP.Slot,
        accessCode: YubiOTP.AccessCodeChange = .unchanged,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTP.SessionError) {
        let newAccessCode = try resolveAccessCode(accessCode, currentAccessCode: currentAccessCode)
        guard configuration.isSupported(by: version) else {
            throw .featureNotSupported(source: .here())
        }
        logger.debug("Writing slot configuration", metadata: ["slot": .stringConvertible(slot.rawValue)])
        try await write(
            command: slot.configCommand,
            config: configuration.configData(accessCode: newAccessCode),
            currentAccessCode: currentAccessCode
        )
    }

    /// Replaces the writable flags of a programmed slot and keeps its secret.
    ///
    /// The update replaces all writable flags. Options that you do not set take their default
    /// values; they do not keep the values of the slot.
    ///
    /// > Note: Requires ``YubiOTP/Feature/update``, available on YubiKey 2.3 or later.
    ///
    /// - Parameters:
    ///   - configuration: The flags to write.
    ///   - slot: The slot to update.
    ///   - accessCode: Whether to keep, replace, or remove the access code of the slot.
    ///   - currentAccessCode: The current access code of the slot, if the slot is protected.
    public func updateConfiguration(
        _ configuration: YubiOTP.SlotUpdate,
        in slot: YubiOTP.Slot,
        accessCode: YubiOTP.AccessCodeChange = .unchanged,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTP.SessionError) {
        let newAccessCode = try resolveAccessCode(accessCode, currentAccessCode: currentAccessCode)
        guard configuration.isSupported(by: version) else {
            throw .featureNotSupported(source: .here())
        }
        // These firmware versions cannot change the access code through an update.
        if (newAccessCode ?? Data(count: otpAccessCodeSize)) != (currentAccessCode ?? Data(count: otpAccessCodeSize)),
            version >= Version("4.3.2")!, version < Version("4.3.6")!
        {
            throw .featureNotSupported(source: .here())
        }
        logger.debug("Updating slot configuration", metadata: ["slot": .stringConvertible(slot.rawValue)])
        try await write(
            command: slot.updateCommand,
            config: configuration.configData(accessCode: newAccessCode),
            currentAccessCode: currentAccessCode
        )
    }

    /// Deletes the configuration of a slot.
    ///
    /// Some YubiKeys reject the deletion of an empty slot.
    ///
    /// - Parameters:
    ///   - slot: The slot to delete.
    ///   - currentAccessCode: The current access code of the slot, if the slot is protected.
    public func deleteConfiguration(
        in slot: YubiOTP.Slot,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTP.SessionError) {
        logger.debug("Deleting slot configuration", metadata: ["slot": .stringConvertible(slot.rawValue)])
        // An all-zero configuration clears the slot.
        try await write(
            command: slot.configCommand,
            config: Data(count: otpConfigSize),
            currentAccessCode: currentAccessCode
        )
    }

    /// Swaps the configurations of the two slots.
    ///
    /// > Note: Requires ``YubiOTP/Feature/swap``, available on YubiKey 2.3 or later.
    public func swapConfigurations() async throws(YubiOTP.SessionError) {
        guard await supports(.swap) else { throw .featureNotSupported(source: .here()) }
        logger.debug("Swapping slot configurations")
        try await write(command: YubiOTP.swapCommand, config: Data(), currentAccessCode: nil)
    }

    /// Replaces the scan-code map that the YubiKey uses to type its output.
    ///
    /// - Parameters:
    ///   - scanMap: The scan codes.
    ///   - currentAccessCode: The current access code, if one is set.
    public func setScanMap(
        _ scanMap: Data,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTP.SessionError) {
        logger.debug("Writing scan map")
        try await write(command: YubiOTP.scanMapCommand, config: scanMap, currentAccessCode: currentAccessCode)
    }

    /// Configures a slot to send an NDEF URI record over NFC.
    ///
    /// > Note: Requires ``YubiOTP/Feature/ndef``, available on YubiKey 3.0 or later.
    ///
    /// - Parameters:
    ///   - slot: The slot to configure.
    ///   - uri: The URI prefix to which the slot's OTP is appended. Defaults to ``YubiOTP/defaultNDEFURI``.
    ///   - currentAccessCode: The current access code of the slot, if the slot is protected.
    public func setNDEFConfiguration(
        in slot: YubiOTP.Slot,
        uri: URL = YubiOTP.defaultNDEFURI,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTP.SessionError) {
        guard await supports(.ndef) else { throw .featureNotSupported(source: .here()) }
        logger.debug("Writing NDEF configuration", metadata: ["slot": .stringConvertible(slot.rawValue)])
        let config = try YubiOTP.buildNDEFConfig(uri: uri)
        try await write(command: slot.ndefCommand, config: config, currentAccessCode: currentAccessCode)
    }

    // MARK: - Private

    // Every configuration write carries the current access code after the configuration.
    private func write(
        command: UInt8,
        config: Data,
        currentAccessCode: Data?
    ) async throws(YubiOTP.SessionError) {
        try validateAccessCode(currentAccessCode)
        try await interface.writeConfig(
            command: command,
            data: config + (currentAccessCode ?? Data(count: otpAccessCodeSize))
        )
        configState = YubiOTP.ConfigState(version: version, flags: await interface.configStateFlags)
        logger.info("Configuration written")
    }

    private func validateAccessCode(_ accessCode: Data?) throws(YubiOTP.SessionError) {
        if let accessCode, accessCode.count != otpAccessCodeSize {
            throw .illegalArgument("Access code must be exactly \(otpAccessCodeSize) bytes", source: .here())
        }
    }

    private func resolveAccessCode(
        _ change: YubiOTP.AccessCodeChange,
        currentAccessCode: Data?
    ) throws(YubiOTP.SessionError) -> Data? {
        try validateAccessCode(currentAccessCode)
        switch change {
        case .unchanged:
            return currentAccessCode
        case .set(let code):
            try validateAccessCode(code)
            guard code.contains(where: { $0 != 0 }) else {
                throw .illegalArgument("Use .remove to clear the access code", source: .here())
            }
            return code
        case .remove:
            return nil
        }
    }
}
