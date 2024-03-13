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

/// Describes the configuration of a YubiKey which can be altered via the Management application.
public struct DeviceConfig {
    
    public let autoEjectTimeout: TimeInterval?
    public let challengeResponseTimeout: TimeInterval?
    public let deviceFlags: UInt8?
    public let enabledCapabilities: [DeviceTransport: UInt]
    
    internal let tagUSBEnabled: TKTLVTag = 0x03
    //    private static final int TAG_USB_ENABLED = 0x03;
    internal let tagAutoEjectTimeout: TKTLVTag = 0x06
    //    private static final int TAG_AUTO_EJECT_TIMEOUT = 0x06;
    internal let tagChallengeResponseTimeout: TKTLVTag = 0x07
    //    private static final int TAG_CHALLENGE_RESPONSE_TIMEOUT = 0x07;
    internal let tagDeviceFlags: TKTLVTag = 0x08
    //    private static final int TAG_DEVICE_FLAGS = 0x08;
    internal let tagNFCEnabled: TKTLVTag = 0x0e
    //    private static final int TAG_NFC_ENABLED = 0x0e;
    internal let tagConfigurationLock: TKTLVTag = 0x0a
    //    private static final int TAG_CONFIGURATION_LOCK = 0x0a;
    internal let tagUnlock: TKTLVTag = 0x0b
    //    private static final int TAG_UNLOCK = 0x0b;
    internal let tagReboot: TKTLVTag = 0x0c
    //    private static final int TAG_REBOOT = 0x0c;
    
    
    public func isApplicationEnabled(_ application: ApplicationType, overTransport transport: DeviceTransport) -> Bool {
        guard let mask = enabledCapabilities[transport] else { return false }
        return (mask & application.rawValue) == application.rawValue
    }
    
    public func deviceConfig(enabling: Bool, application: ApplicationType, overTransport transport: DeviceTransport) -> DeviceConfig? {
        guard let oldMask = enabledCapabilities[transport] else { return nil }
        let newMask = enabling ? oldMask | application.rawValue : oldMask & ~application.rawValue
        var newEnabledCapabilities = enabledCapabilities
        newEnabledCapabilities[transport] = newMask
        
        return DeviceConfig(autoEjectTimeout: autoEjectTimeout,
                            challengeResponseTimeout: challengeResponseTimeout,
                            deviceFlags: deviceFlags,
                            enabledCapabilities: newEnabledCapabilities)
    }
    
    public func deviceConfig(autoEjectTimeout: TimeInterval, challengeResponseTimeout: TimeInterval) -> DeviceConfig {
        return Self.init(autoEjectTimeout: autoEjectTimeout, challengeResponseTimeout: challengeResponseTimeout, deviceFlags: self.deviceFlags, enabledCapabilities: self.enabledCapabilities)
    }
    
    internal func data(reboot: Bool, lockCode: Data?, newLockCode: Data?) throws -> Data {
        var data = Data()
        if reboot {
            data.append(TKBERTLVRecord(tag: tagReboot, value: Data()).data)
        }
        if let lockCode {
            data.append(TKBERTLVRecord(tag: tagUnlock, value: lockCode).data)
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
        if let newLockCode {
            data.append(TKBERTLVRecord(tag: tagConfigurationLock, value: newLockCode).data)
        }
        guard data.count <= 0xff else { throw ManagementSessionError.configTooLarge }
        
        return UInt8(data.count).data + data
    }
}
