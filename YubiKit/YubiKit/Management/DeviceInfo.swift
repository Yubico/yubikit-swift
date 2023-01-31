//
//  DeviceInfo.swift
//  YubiKit
//
//  Created by Jens Utbult on 2023-01-30.
//

import Foundation
import CryptoTokenKit


public enum DeviceTransport {
    case usb, nfc
}

public enum ApplicationType: UInt {
    case otp = 0x01
    case u2f = 0x02
    case opgp = 0x08
    case piv = 0x10
    case oath = 0x20
    case ctap2 = 0x0200
}

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

public struct DeviceInfo {
    public let serialNumber: UInt
    public let version: Version
    public let formFactor: FormFactor
    public let supportedCapabilities: [DeviceTransport: UInt]
    public let isConfigLocked: Bool
    public let isFips: Bool
    public let isSky: Bool
    public let config: DeviceConfig
    
    internal let isUSBSupportedTag: TKTLVTag = 0x01
    internal let serialNumberTag: TKTLVTag = 0x02
    internal let isUSBEnabledTag: TKTLVTag = 0x03
    internal let formFactorTag: TKTLVTag = 0x04
    internal let firmwareVersionTag: TKTLVTag = 0x05
    internal let autoEjectTimeoutTag: TKTLVTag = 0x06
    internal let challengeResponseTimeoutTag: TKTLVTag = 0x07
    internal let deviceFlagsTag: TKTLVTag = 0x08
    internal let isNFCSupportedTag: TKTLVTag = 0x0d
    internal let isNFCEnabledTag: TKTLVTag = 0x0e
    internal let isConfigLockedTag: TKTLVTag = 0x0a
    
    init(withData data: Data, fallbackVersion: Version) throws {
        guard let count = data.bytes.first, count > 0 else { throw "No data" }
        guard let tlvs = TKBERTLVRecord.dictionaryOfData(from: data.subdata(in: 1..<data.count)) else { throw "Failed parsing result" }
        
        if let versionData = tlvs[firmwareVersionTag] {
            guard let parsedVersion = Version(withData: versionData) else { throw ManagementSessionError.versionParseError }
            self.version = parsedVersion
        } else {
            self.version = fallbackVersion
        }
        
        self.isConfigLocked = tlvs[isConfigLockedTag]?.integer == 1
        
        self.serialNumber = tlvs[serialNumberTag]?.integer ?? 0
        
        if let rawFormFactor = tlvs[formFactorTag]?.uint8 {
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
            supportedCapabilities[DeviceTransport.usb] = tlvs[isUSBSupportedTag]?.integer ?? 0
          }
        
        var enabledCapabilities = [DeviceTransport: UInt]()
        if tlvs[isUSBEnabledTag] != nil && version.major != 4 {
              // YK4 reports this incorrectly, instead use supportedCapabilities and USB mode.
            enabledCapabilities[DeviceTransport.usb] = tlvs[isUSBEnabledTag]?.integer ?? 0
          }
        
        if let nfcSupported = tlvs[isNFCSupportedTag]?.integer {
            supportedCapabilities[DeviceTransport.nfc] = nfcSupported
            enabledCapabilities[DeviceTransport.nfc] = tlvs[isNFCEnabledTag]?.integer ?? 0
        }
        self.supportedCapabilities = supportedCapabilities
        
        // DeviceConfig
        let autoEjectTimeout: TimeInterval
        if let timeout = tlvs[autoEjectTimeoutTag]?.integer {
            autoEjectTimeout = TimeInterval(timeout)
        } else {
            autoEjectTimeout = 0
        }
        
        let challengeResponseTimeout: TimeInterval
        if let timeout = tlvs[challengeResponseTimeoutTag]?.integer {
            challengeResponseTimeout = TimeInterval(timeout)
        } else {
            challengeResponseTimeout = 0
        }
        
        let deviceFlags: UInt = tlvs[deviceFlagsTag]?.integer ?? 0
        
        self.config = DeviceConfig(autoEjectTimeout: autoEjectTimeout, challengeResponseTimeout: challengeResponseTimeout, deviceFlags: deviceFlags, enabledCapabilities: enabledCapabilities)
    }
    
    public func isApplicationSupported(_ application: ApplicationType, overTransport transport: DeviceTransport) -> Bool {
        guard let mask = supportedCapabilities[transport] else { return false }
        return (mask & application.rawValue) == application.rawValue
    }
}


extension Data {
    internal var integer: UInt {
        let bytes = self.bytes
        if bytes.isEmpty { return 0 }
        var value: UInt = 0
        bytes.forEach { byte in
            value = value << 8
            value += UInt(byte)
        }
        return value
    }
    
}
