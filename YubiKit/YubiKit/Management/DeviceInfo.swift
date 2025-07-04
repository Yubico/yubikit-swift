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

/// Identifies the type of data transport a YubiKey is using.
public enum DeviceTransport: Sendable {
    case usb, nfc
}

/// The physical form factor of a YubiKey.
public enum FormFactor: UInt8, Sendable {
    /// Used when information about the YubiKey's form factor isn't available.
    case unknown = 0x00
    /// A keychain-sized YubiKey with a USB-A connector.
    case usbAKeychain = 0x01
    /// A nano-sized YubiKey with a USB-A connector.
    case usbANano = 0x02
    /// A keychain-sized YubiKey with a USB-C connector.
    case usbCKeychain = 0x03
    /// A nano-sized YubiKey with a USB-C connector.
    case usbCNano = 0x04
    /// A keychain-sized YubiKey with both USB-C and Lightning connectors.
    case usbCLightning = 0x05
    /// A keychain-sized YubiKey with fingerprint sensor and USB-A connector.
    case usbABio = 0x06
    /// A keychain-sized YubiKey with fingerprint sensor and USB-C connector.
    case usbCBio = 0x07
}

/// Contains metadata, including Device Configuration, of a YubiKey.
public struct DeviceInfo: Sendable, CustomStringConvertible {

    public var description: String {
        """
        YubiKey \(formFactor) \(version) (#\(serialNumber))
        Supported capabilities: \(supportedCapabilities)
        Enabled capabilities: \(config.enabledCapabilities)
        isConfigLocked: \(isConfigLocked)
        isFips: \(isFips)
        isSky: \(isSky)
        partNumber: \(String(describing: partNumber))
        isFipsCapable: \(isFIPSCapable)
        isFipsApproved: \(isFIPSApproved)
        pinComplexity: \(pinComplexity)
        resetBlocked: \(isResetBlocked)
        fpsVersion: \(String(describing: fpsVersion))
        stmVersion: \(String(describing: stmVersion))
        """
    }

    /// The serial number of the YubiKey, if available.
    ///
    /// The serial number can be read if the YubiKey has a serial number, and one of the YubiOTP slots
    /// is configured with the SERIAL_API_VISIBLE flag.
    public let serialNumber: UInt
    /// The version number of the YubiKey firmware.
    public let version: Version
    /// the form factor of the YubiKey.
    public let formFactor: FormFactor
    /// The part number of the YubiKey.
    public let partNumber: String?
    /// FIPS capable flags.
    public let isFIPSCapable: UInt
    /// FIPS approved flags.
    public let isFIPSApproved: UInt
    /// The FPS version.
    public let fpsVersion: Version?
    /// The STM version
    public let stmVersion: Version?
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
    /// PIN complexity
    public let pinComplexity: Bool
    /// The reset blocked flag.
    public let isResetBlocked: UInt

    internal let tagUSBSupported: TKTLVTag = 0x01
    internal let tagSerialNumber: TKTLVTag = 0x02
    internal let tagUSBEnabled: TKTLVTag = 0x03
    internal let tagFormFactor: TKTLVTag = 0x04
    internal let tagFirmwareVersion: TKTLVTag = 0x05
    internal let tagAutoEjectTimeout: TKTLVTag = 0x06
    internal let tagChallengeResponseTimeout: TKTLVTag = 0x07
    internal let tagDeviceFlags: TKTLVTag = 0x08
    internal let tagNFCSupported: TKTLVTag = 0x0d
    internal let tagNFCEnabled: TKTLVTag = 0x0e
    internal let tagConfigLocked: TKTLVTag = 0x0a
    internal let tagPartNumber: TKTLVTag = 0x13
    internal let tagFIPSCapable: TKTLVTag = 0x14
    internal let tagFIPSApproved: TKTLVTag = 0x15
    internal let tagPINComplexity: TKTLVTag = 0x16
    internal let tagNFCRestricted: TKTLVTag = 0x17
    internal let tagResetBlocked: TKTLVTag = 0x18
    internal let tagFPSVersion: TKTLVTag = 0x20
    internal let tagSTMVersion: TKTLVTag = 0x21

    internal init(withTlvs tlvs: [TKTLVTag: Data], fallbackVersion: Version) throws {

        self.isConfigLocked = tlvs[tagConfigLocked]?.integer == 1
        self.serialNumber = tlvs[tagSerialNumber]?.integer ?? 0

        if let rawFormFactor = tlvs[tagFormFactor]?.uint8 {
            self.isFips = (rawFormFactor & 0x80) != 0
            self.isSky = (rawFormFactor & 0x40) != 0
            if let formFactor = FormFactor(rawValue: rawFormFactor & 0x0f) {
                self.formFactor = formFactor
            } else {
                self.formFactor = .unknown
            }
        } else {
            self.formFactor = .unknown
            self.isFips = false
            self.isSky = false
        }

        self.isFIPSCapable = Capability.translateMaskFrom(fipsMask: tlvs[tagFIPSCapable]?.integer ?? 0)
        self.isFIPSApproved = Capability.translateMaskFrom(fipsMask: tlvs[tagFIPSApproved]?.integer ?? 0)

        self.pinComplexity = tlvs[tagPINComplexity]?.integer == 1

        self.isResetBlocked = tlvs[tagResetBlocked]?.integer ?? 0

        if let data = tlvs[tagFirmwareVersion], let version = Version(withData: data) {
            self.version = version
        } else {
            self.version = fallbackVersion
        }
        if let data = tlvs[tagFPSVersion], let version = Version(withData: data), version.description != "0.0.0" {
            self.fpsVersion = version
        } else {
            self.fpsVersion = nil
        }
        if let data = tlvs[tagSTMVersion], let version = Version(withData: data), version.description != "0.0.0" {
            self.stmVersion = version
        } else {
            self.stmVersion = nil
        }

        self.partNumber = tlvs[tagPartNumber]?.stringUTF8.flatMap { $0.isEmpty ? nil : $0 }

        var supportedCapabilities = [DeviceTransport: UInt]()
        if version.major == 4 && version.minor == 2 && version.micro == 4 {
            // 4.2.4 doesn't report supported capabilities correctly, but they are always 0x3f.
            supportedCapabilities[DeviceTransport.usb] = 0x3f
        } else {
            supportedCapabilities[DeviceTransport.usb] = tlvs[tagUSBSupported]?.integer ?? 0
        }

        if let nfcSupported = tlvs[tagNFCSupported]?.integer {
            supportedCapabilities[DeviceTransport.nfc] = nfcSupported
        }
        self.supportedCapabilities = supportedCapabilities

        self.config = try DeviceConfig(withTlvs: tlvs, version: self.version)
    }

    /// Returns whether or not a specific transport is available on this YubiKey.
    public func hasTransport(_ transport: DeviceTransport) -> Bool {
        supportedCapabilities.keys.contains(transport)
    }

    /// Returns whether the application is supported over the specific transport.
    public func isApplicationSupported(_ application: Capability, overTransport transport: DeviceTransport) -> Bool {
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
