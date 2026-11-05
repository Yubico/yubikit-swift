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

extension DeviceInfo {
    // Reconstruct incomplete metadata on older keys; leave enabled configuration unknown.
    internal static func read(
        connection: SmartCardConnection,
        usbProductID: UInt16? = nil
    ) async throws -> DeviceInfo {
        try Task.checkCancellation()
        var version: Version?
        var isYubiKey = false
        do {
            let session = try await Management.Session.makeSession(connection: connection)
            version = session.version
            isYubiKey = true
            if await session.supports(.deviceInfo) {
                return try await session.getDeviceInfo()
            }
        } catch ManagementSessionError.featureNotSupported {
            // NEO and other older devices may not expose Management.
        }

        var serial: UInt = 0
        var capabilities: UInt = 0
        do {
            let otp = try await YubiOTP.Session.makeSession(connection: connection)
            isYubiKey = true
            if let knownVersion = version {
                if knownVersion.major == 3 { version = max(knownVersion, otp.version) }
            } else {
                version = otp.version
            }
            capabilities |= Capability.otp.rawValue
            do {
                serial = try await otp.getSerialNumber()
            } catch {
                // Serial visibility is optional; transport and parsing failures are not.
                switch error {
                case .featureNotSupported, .failedResponse: break
                default: throw error
                }
            }
        } catch YubiOTP.SessionError.featureNotSupported {
        }

        let applets: [(Data, Capability)] = [
            (Data([0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01]), .u2f),
            (Data([0xa0, 0x00, 0x00, 0x03, 0x08]), .piv),
            (Data([0xd2, 0x76, 0x00, 0x01, 0x24, 0x01]), .openPGP),
            (Data([0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]), .oath),
            (Data([0xa0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02]), .u2f),  // Legacy Yubico U2F AID.
        ]
        for (aid, capability) in applets {
            if capabilities & capability.rawValue != 0 { continue }
            try Task.checkCancellation()
            do {
                _ = try await SmartCardInterface<ManagementSessionError>.sendPlainStatic(
                    connection: connection,
                    apdu: APDU(cla: 0, ins: 0xa4, p1: 4, p2: 0, command: aid),
                    insSendRemaining: 0xc0
                )
                capabilities |= capability.rawValue
                isYubiKey = isYubiKey || aid.starts(with: [0xa0, 0, 0, 5, 0x27])
            } catch {
                switch error.responseStatus?.rawStatus {
                case 0x6a81, 0x6a82, 0x6b00, 0x6999, 0x6d00: break
                case 0x6285, 0x6985:
                    // OpenPGP can be inactive after an interrupted reset.
                    guard capability == .openPGP else { throw error }
                default: throw error
                }
            }
        }
        guard isYubiKey else {
            throw ManagementSessionError.featureNotSupported(source: .here())
        }
        return legacyInfo(
            version: version ?? Version("3.0.0")!,
            serialNumber: serial,
            usbProductID: usbProductID,
            probedCapabilities: capabilities
        )
    }

    internal static func read(
        connection: FIDOConnection,
        usbProductID: UInt16? = nil,
        usbVendorID: UInt16? = nil
    ) async throws -> DeviceInfo {
        try Task.checkCancellation()
        var pid = usbProductID
        var vid = usbVendorID
        #if os(macOS)
        if let hid = connection as? HIDFIDOConnection {
            pid = pid ?? hid.usbProductID
            vid = vid ?? hid.device.usbVendorID
        }
        #endif
        guard vid == nil || vid == 0x1050 else {
            throw ManagementSessionError.featureNotSupported(source: .here())
        }
        let session = try await Management.Session.makeSession(connection: connection)
        // Pre-YubiKey-4 CTAPHID versions are not firmware versions; the PID identifies the family.
        if vid == 0x1050, let pid {
            switch pid {
            case 0x0110...0x0116:
                return legacyInfo(
                    version: Version("3.0.0")!,
                    usbProductID: pid,
                    probedCapabilities: Capability.u2f.rawValue
                )
            case 0x0410:
                return legacyInfo(
                    version: Version("4.0.0")!,
                    usbProductID: pid,
                    probedCapabilities: Capability.u2f.rawValue
                )
            default: break
            }
        }
        if await session.supports(.deviceInfo) {
            return try await session.getDeviceInfo()
        }
        guard vid == 0x1050 else {
            throw ManagementSessionError.featureNotSupported(source: .here())
        }
        guard let pid else {
            return DeviceInfo(version: session.version, supportedCapabilities: [.usb: Capability.u2f.rawValue])
        }
        return legacyInfo(version: session.version, usbProductID: pid, probedCapabilities: Capability.u2f.rawValue)
    }

    internal static func read(
        connection: OTPConnection,
        usbProductID: UInt16? = nil
    ) async throws -> DeviceInfo {
        try Task.checkCancellation()
        var version: Version?
        do {
            let session = try await Management.Session.makeSession(connection: connection)
            version = session.version
            if await session.supports(.deviceInfo) {
                return try await session.getDeviceInfo()
            }
        } catch ManagementSessionError.featureNotSupported {
        }
        let otp = try await YubiOTP.Session.makeSession(connection: connection)
        var serial: UInt = 0
        do {
            serial = try await otp.getSerialNumber()
        } catch {
            switch error {
            case .commandRejected, .featureNotSupported: break
            default: throw error
            }
        }
        var pid = usbProductID
        #if os(macOS)
        if pid == nil { pid = (connection as? HIDOTPConnection)?.usbProductID }
        #endif
        return legacyInfo(
            version: version ?? otp.version,
            serialNumber: serial,
            usbProductID: pid,
            probedCapabilities: Capability.otp.rawValue
        )
    }

    internal static func legacyInfo(
        version: Version,
        serialNumber: UInt = 0,
        usbProductID: UInt16? = nil,
        probedCapabilities: UInt
    ) -> DeviceInfo {
        var capabilities = probedCapabilities
        let isNEO = usbProductID.map { (0x0110...0x0116).contains($0) } ?? (version.major == 3)
        let isSKY = usbProductID == 0x0120
        if isNEO {
            if usbProductID != nil {
                capabilities |=
                    Capability.otp.rawValue | Capability.oath.rawValue | Capability.piv.rawValue
                    | Capability.openPGP.rawValue
            }
            if version >= Version("3.3.0")! || usbProductID.map({ (0x0113...0x0116).contains($0) }) == true {
                capabilities |= Capability.u2f.rawValue
            }
        } else if usbProductID == 0x0410 {
            capabilities |= Capability.otp.rawValue | Capability.u2f.rawValue
        } else if isSKY {
            capabilities = Capability.u2f.rawValue
        }
        var supported: [DeviceTransport: UInt] = [.usb: capabilities]
        if isNEO { supported[.nfc] = capabilities }
        return DeviceInfo(
            version: version,
            serialNumber: serialNumber,
            supportedCapabilities: supported,
            isFIPS: version >= Version("4.4.0")! && version < Version("4.5.0")!,
            isSKY: isSKY
        )
    }
}
