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

/// Identifies the type of data transport a YubiKey is using.
public enum DeviceTransport {
    case usb, nfc
}

/// Identifies a feature (typically an application) on a YubiKey which may or may not be supported, and which can be enabled or disabled.
public enum ApplicationType: UInt {
    /// Identifies the YubiOTP application.
    case otp = 0x01
    /// Identifies the U2F (CTAP1) portion of the FIDO application.
    case u2f = 0x02
    /// Identifies the OpenPGP application, implementing the OpenPGP Card protocol.
    case opgp = 0x08
    /// Identifies the PIV application, implementing the PIV protocol.
    case piv = 0x10
    /// Identifies the OATH application, implementing the YKOATH protocol.
    case oath = 0x20
    /// Identifies the FIDO2 (CTAP2) portion of the FIDO application.
    case ctap2 = 0x0200
}

/// The physical form factor of a YubiKey.
public enum FormFactor: UInt8 {
    // Used when information about the YubiKey's form factor isn't available.
    case unknown = 0x00
    // A keychain-sized YubiKey with a USB-A connector.
    case usbAKeychain = 0x01
    // A nano-sized YubiKey with a USB-A connector.
    case usbANano = 0x02
    // A keychain-sized YubiKey with a USB-C connector.
    case usbCKeychain = 0x03
    // A nano-sized YubiKey with a USB-C connector.
    case usbCNano = 0x04
    // A keychain-sized YubiKey with both USB-C and Lightning connectors.
    case usbCLightning = 0x05
    // A keychain-sized YubiKey with fingerprint sensor and USB-A connector.
    case usbABio = 0x06
    // A keychain-sized YubiKey with fingerprint sensor and USB-C connector.
    case usbCBio = 0x07
}

/// Contains metadata, including Device Configuration, of a YubiKey.
public struct DeviceInfo {
    /// Returns the serial number of the YubiKey, if available.
    ///
    /// The serial number can be read if the YubiKey has a serial number, and one of the YubiOTP slots
    /// is configured with the SERIAL_API_VISIBLE flag.
    public let serialNumber: UInt
    /// Returns the version number of the YubiKey firmware.
    public let version: Version
    /// Returns the form factor of the YubiKey.
    public let formFactor: FormFactor
    /// Returns the supported (not necessarily enabled) capabilities for a given transport.
    public let supportedCapabilities: [DeviceTransport: UInt]
    /// Returns whether or not a Configuration Lock is set for the Management application on the YubiKey.
    public let isConfigLocked: Bool
    /// Returns whether or not this is a FIPS compliant device.
    public let isFips: Bool
    /// Returns whether or not this is a Security key.
    public let isSky: Bool
    /// The mutable configuration of the YubiKey.
    public let config: DeviceConfig
    
    internal let tagIsUSBSupported: TKTLVTag = 0x01
    internal let tagSerialNumber: TKTLVTag = 0x02
    internal let tagIsUSBEnabled: TKTLVTag = 0x03
    internal let tagFormFactor: TKTLVTag = 0x04
    internal let tagFirmwareVersion: TKTLVTag = 0x05
    internal let tagAutoEjectTimeout: TKTLVTag = 0x06
    internal let tagChallengeResponseTimeout: TKTLVTag = 0x07
    internal let tagDeviceFlags: TKTLVTag = 0x08
    internal let tagIsNFCSupported: TKTLVTag = 0x0d
    internal let tagIsNFCEnabled: TKTLVTag = 0x0e
    internal let tagIsConfigLocked: TKTLVTag = 0x0a
    
    internal init(withData data: Data, fallbackVersion: Version) throws {
        guard let count = data.bytes.first, count > 0 else { throw ManagementSessionError.missingData }
        guard let tlvs = TKBERTLVRecord.dictionaryOfData(from: data.subdata(in: 1..<data.count)) else { throw ManagementSessionError.unexpectedData }
        
        if let versionData = tlvs[tagFirmwareVersion] {
            guard let parsedVersion = Version(withData: versionData) else { throw ManagementSessionError.unexpectedData }
            self.version = parsedVersion
        } else {
            self.version = fallbackVersion
        }
        
        self.isConfigLocked = tlvs[tagIsConfigLocked]?.integer == 1
        
        self.serialNumber = tlvs[tagSerialNumber]?.integer ?? 0
        
        if let rawFormFactor = tlvs[tagFormFactor]?.uint8 {
            self.isFips = (rawFormFactor & 0x80) != 0
            self.isSky = (rawFormFactor & 0x40) != 0
            if let formFactor = FormFactor(rawValue: rawFormFactor) {
                self.formFactor = formFactor
            } else {
                self.formFactor = .unknown
            }
        } else {
            self.formFactor = .unknown
            self.isFips = false
            self.isSky = false
        }
        
        var supportedCapabilities = [DeviceTransport: UInt]()
        if (version.major == 4 && version.minor == 2 && version.micro == 4) {
              // 4.2.4 doesn't report supported capabilities correctly, but they are always 0x3f.
            supportedCapabilities[DeviceTransport.usb] = 0x3f
          } else {
            supportedCapabilities[DeviceTransport.usb] = tlvs[tagIsUSBSupported]?.integer ?? 0
          }
        
        var enabledCapabilities = [DeviceTransport: UInt]()
        if tlvs[tagIsUSBEnabled] != nil && version.major != 4 {
              // YK4 reports this incorrectly, instead use supportedCapabilities and USB mode.
            enabledCapabilities[DeviceTransport.usb] = tlvs[tagIsUSBEnabled]?.integer ?? 0
          }
        
        if let nfcSupported = tlvs[tagIsNFCSupported]?.integer {
            supportedCapabilities[DeviceTransport.nfc] = nfcSupported
            enabledCapabilities[DeviceTransport.nfc] = tlvs[tagIsNFCEnabled]?.integer ?? 0
        }
        self.supportedCapabilities = supportedCapabilities
        
        // DeviceConfig
        let autoEjectTimeout: TimeInterval
        if let timeout = tlvs[tagAutoEjectTimeout]?.integer {
            autoEjectTimeout = TimeInterval(timeout)
        } else {
            autoEjectTimeout = 0
        }
        
        let challengeResponseTimeout: TimeInterval
        if let timeout = tlvs[tagChallengeResponseTimeout]?.integer {
            challengeResponseTimeout = TimeInterval(timeout)
        } else {
            challengeResponseTimeout = 0
        }
        
        let deviceFlags = UInt8(tlvs[tagDeviceFlags]?.integer ?? 0)
        
        self.config = DeviceConfig(autoEjectTimeout: autoEjectTimeout, challengeResponseTimeout: challengeResponseTimeout, deviceFlags: deviceFlags, enabledCapabilities: enabledCapabilities)
    }
    
    /// Returns whether or not a specific transport is available on this YubiKey.
    public func hasTransport(_ transport: DeviceTransport) -> Bool {
        return supportedCapabilities.keys.contains(transport)
    }
    
    /// Returns whether the application is supported over the specific transport.
    public func isApplicationSupported(_ application: ApplicationType, overTransport transport: DeviceTransport) -> Bool {
        guard let mask = supportedCapabilities[transport] else { return false }
        return (mask & application.rawValue) == application.rawValue
    }
}


extension Data {
    internal var integer: UInt? {
        let bytes = self.bytes
        guard !bytes.isEmpty else { return 0 }
        guard bytes.count <= UInt.bitWidth / UInt8.bitWidth else { return nil }
        var value: UInt = 0
        bytes.forEach { byte in
            value = value << 8
            value += UInt(byte)
        }
        return value
    }
    
}
