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
    /// USB transport.
    case usb
    /// NFC (Near Field Communication) transport.
    case nfc
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

    /// String representation of the device information.
    public var description: String {
        """
        YubiKey \(formFactor) \(version) (#\(serialNumber))
        Supported capabilities: \(supportedCapabilities)
        Enabled capabilities: \(config.enabledCapabilities)
        isConfigLocked: \(isConfigLocked)
        isFips: \(isFIPS)
        isSKY: \(isSKY)
        partNumber: \(String(describing: partNumber))
        fipsCapabilityFlags: \(fipsCapabilityFlags)
        fipsApprovalFlags: \(fipsApprovalFlags)
        pinComplexity: \(pinComplexity)
        resetBlockedFlags: \(resetBlockedFlags)
        fpsVersion: \(String(describing: fpsVersion))
        stmVersion: \(String(describing: stmVersion))
        """
    }

    /// The serial number of the YubiKey, if available.
    ///
    /// The serial number can be read if the YubiKey has a serial number, and one of the YubiOTP slots
    /// is configured with the SERIAL_API_VISIBLE flag.
    public let serialNumber: UInt
    /// The firmware version, resolved from the qualifier for development and prerelease firmware.
    public let version: Version
    /// Firmware release metadata, including prerelease type and build iteration.
    /// Defaults to a final release with iteration zero when unavailable.
    public let versionQualifier: VersionQualifier
    /// the form factor of the YubiKey.
    public let formFactor: FormFactor
    /// The part number of the YubiKey.
    public let partNumber: String?
    internal let reportedName: String?
    /// FIPS capable flags.
    public let fipsCapabilityFlags: UInt
    /// FIPS approved flags.
    public let fipsApprovalFlags: UInt
    /// The FPS version.
    public let fpsVersion: Version?
    /// The STM version
    public let stmVersion: Version?
    /// Returns the supported (not necessarily enabled) capabilities for a given transport.
    public let supportedCapabilities: [DeviceTransport: UInt]
    /// Returns whether or not a Configuration Lock is set for the Management application on the YubiKey.
    public let isConfigLocked: Bool
    /// Returns whether or not this is a FIPS compliant device.
    public let isFIPS: Bool
    /// Returns whether or not this is a Security key.
    public let isSKY: Bool
    /// The mutable configuration of the YubiKey.
    public let config: DeviceConfig
    /// PIN complexity
    public let pinComplexity: Bool
    /// The reset blocked flag.
    public let resetBlockedFlags: UInt

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
    internal let tagVersionQualifier: TKTLVTag = 0x19
    internal let tagName: TKTLVTag = 0x1b
    internal let tagFPSVersion: TKTLVTag = 0x20
    internal let tagSTMVersion: TKTLVTag = 0x21

    internal init(
        version: Version,
        serialNumber: UInt = 0,
        formFactor: FormFactor = .unknown,
        supportedCapabilities: [DeviceTransport: UInt],
        isFIPS: Bool = false,
        isSKY: Bool = false,
        pinComplexity: Bool = false,
        config: DeviceConfig = DeviceConfig(enabledCapabilities: [:])
    ) {
        self.version = version
        self.versionQualifier = VersionQualifier(version: version, releaseType: .final, iteration: 0)
        self.serialNumber = serialNumber
        self.formFactor = formFactor
        self.supportedCapabilities = supportedCapabilities
        self.isFIPS = isFIPS
        self.isSKY = isSKY
        self.pinComplexity = pinComplexity
        self.reportedName = nil
        self.config = config
        self.isConfigLocked = false
        self.partNumber = nil
        self.fipsCapabilityFlags = 0
        self.fipsApprovalFlags = 0
        self.resetBlockedFlags = 0
        self.fpsVersion = nil
        self.stmVersion = nil
    }

    internal init(withTlvs tlvs: [TKTLVTag: Data], fallbackVersion: Version) {

        self.isConfigLocked = tlvs[tagConfigLocked]?.integer == 1
        self.serialNumber = tlvs[tagSerialNumber]?.integer ?? 0

        if let rawFormFactor = tlvs[tagFormFactor]?.uint8 {
            self.isFIPS = (rawFormFactor & 0x80) != 0
            self.isSKY = (rawFormFactor & 0x40) != 0
            if let formFactor = FormFactor(rawValue: rawFormFactor & 0x0f) {
                self.formFactor = formFactor
            } else {
                self.formFactor = .unknown
            }
        } else {
            self.formFactor = .unknown
            self.isFIPS = false
            self.isSKY = false
        }

        self.fipsCapabilityFlags = Capability.translateMaskFrom(fipsMask: tlvs[tagFIPSCapable]?.integer ?? 0)
        self.fipsApprovalFlags = Capability.translateMaskFrom(fipsMask: tlvs[tagFIPSApproved]?.integer ?? 0)

        self.pinComplexity = tlvs[tagPINComplexity]?.integer == 1

        self.resetBlockedFlags = tlvs[tagResetBlocked]?.integer ?? 0

        let firmwareVersion = tlvs[tagFirmwareVersion].flatMap { Version(withData: $0) } ?? fallbackVersion
        let qualifier = tlvs[tagVersionQualifier].flatMap { TKBERTLVRecord.dictionaryOfData(from: $0) }
        self.versionQualifier = VersionQualifier(
            version: qualifier?[0x01].flatMap { Version(withData: $0) } ?? firmwareVersion,
            releaseType: qualifier?[0x02]?.integer.flatMap { UInt8(exactly: $0) }
                .flatMap { VersionQualifier.ReleaseType(rawValue: $0) } ?? .final,
            iteration: qualifier?[0x03]?.integer.flatMap { UInt32(exactly: $0) } ?? 0
        )
        // Prerelease firmware uses the qualifier's behavioral version.
        self.version =
            firmwareVersion == .development || versionQualifier.releaseType != .final
            ? versionQualifier.version : firmwareVersion
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
        self.reportedName = tlvs[tagName].flatMap { String(data: $0, encoding: .utf8) }.flatMap {
            $0.isEmpty ? nil : $0
        }

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

        self.config = DeviceConfig(withTlvs: tlvs, version: self.version)
    }

    /// Returns whether or not a specific transport is available on this YubiKey.
    public func hasTransport(_ transport: DeviceTransport) -> Bool {
        supportedCapabilities.keys.contains(transport)
    }

    /// Returns whether the application is supported over the specific transport.
    public func isApplicationSupported(_ application: Capability, over transport: DeviceTransport) -> Bool {
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
