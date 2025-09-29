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

import CryptoTokenKit
import Foundation

/// Describes the configuration of a YubiKey which can be altered via the Management application.
public struct DeviceConfig: Sendable {

    /// The timeout used when in CCID-only mode with flag eject enabled.
    public let autoEjectTimeout: TimeInterval?

    /// The timeout value used by the YubiOTP application when waiting for a user presence check (physical touch).
    public let challengeResponseTimeout: TimeInterval?

    /// The device flags that are set.
    public let deviceFlags: UInt8?

    /// The currently enabled capabilities for a given ``DeviceTransport``. The enabled capabilities are represented as
    /// ``Capability`` bits being set (1) or not (0).
    ///
    ///>Note: This method will return nil if the given transport is not supported by the YubiKey, OR if the enabled
    /// capabilities state isn't readable. The YubiKey 4 series, for example, does not return enabled-status for USB
    public let enabledCapabilities: [DeviceTransport: UInt]
    public let isNFCRestricted: Bool?

    internal let tagUSBEnabled: TKTLVTag = 0x03
    internal let tagAutoEjectTimeout: TKTLVTag = 0x06
    internal let tagChallengeResponseTimeout: TKTLVTag = 0x07
    internal let tagDeviceFlags: TKTLVTag = 0x08
    internal let tagNFCSupported: TKTLVTag = 0x0d
    internal let tagNFCEnabled: TKTLVTag = 0x0e
    internal let tagConfigurationLock: TKTLVTag = 0x0a
    internal let tagUnlock: TKTLVTag = 0x0b
    internal let tagReboot: TKTLVTag = 0x0c
    internal let tagNFCRestricted: TKTLVTag = 0x17

    /// Creates a new DeviceConfig with the specified settings.
    /// - Parameters:
    ///   - autoEjectTimeout: The timeout used when in CCID-only mode with flag eject enabled.
    ///   - challengeResponseTimeout: The timeout value used by the YubiOTP application when waiting for a user presence check (physical touch).
    ///   - deviceFlags: The device flags that are set.
    ///   - enabledCapabilities: The enabled capabilities for each transport.
    ///   - isNFCRestricted: Indicates whether NFC is restricted.
    public init(
        autoEjectTimeout: TimeInterval? = nil,
        challengeResponseTimeout: TimeInterval? = nil,
        deviceFlags: UInt8? = nil,
        enabledCapabilities: [DeviceTransport: UInt],
        isNFCRestricted: Bool? = nil
    ) {
        self.autoEjectTimeout = autoEjectTimeout
        self.challengeResponseTimeout = challengeResponseTimeout
        self.deviceFlags = deviceFlags
        self.enabledCapabilities = enabledCapabilities
        self.isNFCRestricted = isNFCRestricted
    }

    internal init(withTlvs tlvs: [TKTLVTag: Data], version: Version) throws {
        if let timeout = tlvs[tagAutoEjectTimeout]?.integer {
            self.autoEjectTimeout = TimeInterval(timeout)
        } else {
            self.autoEjectTimeout = 0
        }

        if let timeout = tlvs[tagChallengeResponseTimeout]?.integer {
            self.challengeResponseTimeout = TimeInterval(timeout)
        } else {
            self.challengeResponseTimeout = 0
        }

        self.deviceFlags = tlvs[tagDeviceFlags]?.uint8

        var enabledCapabilities = [DeviceTransport: UInt]()
        if tlvs[tagUSBEnabled] != nil && version.major != 4 {
            // YK4 reports this incorrectly, instead use supportedCapabilities and USB mode.
            enabledCapabilities[DeviceTransport.usb] = tlvs[tagUSBEnabled]?.integer ?? 0
        }

        if tlvs[tagNFCSupported] != nil {
            enabledCapabilities[DeviceTransport.nfc] = tlvs[tagNFCEnabled]?.integer ?? 0
        }
        self.enabledCapabilities = enabledCapabilities
        if let isNFCRestricted = tlvs[tagNFCRestricted]?.integer {
            self.isNFCRestricted = isNFCRestricted == 1
        } else {
            self.isNFCRestricted = nil
        }
    }

    public func isApplicationEnabled(_ application: Capability, over transport: DeviceTransport) -> Bool {
        guard let mask = enabledCapabilities[transport] else { return false }
        return (mask & application.rawValue) == application.rawValue
    }

    private func with(
        application: Capability,
        enabled: Bool,
        over transport: DeviceTransport
    ) -> DeviceConfig {
        guard let oldMask = enabledCapabilities[transport] else {
            // Transport not available - return unchanged config for chaining
            return self
        }
        let newMask = enabled ? oldMask | application.rawValue : oldMask & ~application.rawValue
        var newEnabledCapabilities = enabledCapabilities
        newEnabledCapabilities[transport] = newMask

        return DeviceConfig(
            autoEjectTimeout: autoEjectTimeout,
            challengeResponseTimeout: challengeResponseTimeout,
            deviceFlags: deviceFlags,
            enabledCapabilities: newEnabledCapabilities,
            isNFCRestricted: self.isNFCRestricted
        )
    }

    /// Enable an application over the specified transport.
    /// - Note: If the specified transport is not supported by this device configuration, returns the configuration unchanged.
    public func enable(application: Capability, over transport: DeviceTransport) -> DeviceConfig {
        with(application: application, enabled: true, over: transport)
    }

    /// Disable an application over the specified transport.
    /// - Note: If the specified transport is not supported by this device configuration, returns the configuration unchanged.
    public func disable(application: Capability, over transport: DeviceTransport) -> DeviceConfig {
        with(application: application, enabled: false, over: transport)
    }

    public func with(
        autoEjectTimeout: TimeInterval? = nil,
        challengeResponseTimeout: TimeInterval? = nil,
        nfcRestricted: Bool? = nil
    ) -> DeviceConfig {
        Self.init(
            autoEjectTimeout: autoEjectTimeout ?? self.autoEjectTimeout,
            challengeResponseTimeout: challengeResponseTimeout ?? self.challengeResponseTimeout,
            deviceFlags: self.deviceFlags,
            enabledCapabilities: self.enabledCapabilities,
            isNFCRestricted: nfcRestricted ?? self.isNFCRestricted
        )
    }

    internal func data(reboot: Bool, lockCode: Data?, newLockCode: Data?) throws -> Data {
        var data = Data()
        if reboot {
            data.append(TKBERTLVRecord(tag: tagReboot, value: Data()).data)
        }
        if let lockCode {
            data.append(TKBERTLVRecord(tag: tagUnlock, value: lockCode).data)
        }
        if let newLockCode {
            data.append(TKBERTLVRecord(tag: tagConfigurationLock, value: newLockCode).data)
        }
        if let usbEnabled = enabledCapabilities[.usb] {
            data.append(TKBERTLVRecord(tag: tagUSBEnabled, value: UInt16(usbEnabled).bigEndian.data).data)
        }
        if let nfcEnabled = enabledCapabilities[.nfc] {
            data.append(TKBERTLVRecord(tag: tagNFCEnabled, value: UInt16(nfcEnabled).bigEndian.data).data)
        }
        if let autoEjectTimeout {
            data.append(TKBERTLVRecord(tag: tagAutoEjectTimeout, value: UInt16(autoEjectTimeout).bigEndian.data).data)
        }
        if let challengeResponseTimeout {
            let timeout = UInt8(challengeResponseTimeout)
            data.append(TKBERTLVRecord(tag: tagChallengeResponseTimeout, value: timeout.data).data)
        }
        if let deviceFlags {
            data.append(TKBERTLVRecord(tag: tagDeviceFlags, value: deviceFlags.data).data)
        }
        if let isNFCRestricted, isNFCRestricted {
            data.append(TKBERTLVRecord(tag: tagNFCRestricted, value: UInt8(0x01).data).data)
        }

        guard data.count <= 0xff else { throw ManagementSessionError.configTooLarge }

        return UInt8(data.count).data + data
    }
}
