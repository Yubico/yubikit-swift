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
import YubiKit
@_spi(YubiInternal) import YubiKitIntegrationScenarios
import YubiKitTwinSupport

/// Runs integration scenarios against TwinKit's in-process YubiKey.
///
/// A run targets one transport, the way a real session does — you are either plugged in or tapping
/// a card. `YUBIKIT_TWINKIT_TRANSPORT=nfc` switches the whole run to contactless, where CCID is the
/// only path: the keyboard (OTP) and FIDO HID interfaces are USB-only, so CTAP2 falls back to CCID.
@_spi(YubiInternal) public struct TwinKitConnectionProvider: ConnectionProvider {
    public static let environmentConfigurationError: String? =
        TwinKitBackend.environmentProfileConfigurationError ?? transportConfigurationError
            ?? descriptorConfigurationError

    private static let transportEnvironmentKey = "YUBIKIT_TWINKIT_TRANSPORT"

    private static let descriptorConfigurationError: String? = {
        do {
            _ = try TwinKitBackend.shared.descriptor()
            return nil
        } catch {
            return "TwinKit descriptor failed: \(error)"
        }
    }()

    private static let transportConfigurationError: String? = {
        guard let value = ProcessInfo.processInfo.environment[transportEnvironmentKey]?.lowercased(),
            !value.isEmpty
        else { return nil }
        guard ["usb", "nfc"].contains(value) else {
            return "invalid \(transportEnvironmentKey) '\(value)' (expected usb or nfc)"
        }
        if value == "nfc", let descriptor = try? TwinKitBackend.shared.descriptor(),
            descriptor.nfcCapabilities == 0 {
            return "\(transportEnvironmentKey)=nfc requires a device with NFC"
        }
        return nil
    }()

    public static var environmentTransport: DeviceTransport {
        ProcessInfo.processInfo.environment[transportEnvironmentKey]?.lowercased() == "nfc" ? .nfc : .usb
    }

    public var capabilities: ProviderCapabilities {
        let descriptor = try? TwinKitBackend.shared.descriptor()
        let isNFC = deviceTransport == .nfc
        let usb = descriptor?.usbInterfaces ?? 0
        return ProviderCapabilities(
            hasFIDO: !isNFC && usb & USBInterface.fido != 0,
            hasOTP: !isNFC && usb & USBInterface.otp != 0,
            hasSmartCard: isNFC ? (descriptor?.nfcCapabilities ?? 0) != 0 : usb & USBInterface.ccid != 0,
            supportsSecureChannel: descriptor?.supportsSecureChannel == true,
            isVirtual: true
        )
    }
    public let deviceTransport: DeviceTransport
    public var ctap2Transport: CTAP2Transport {
        deviceTransport == .nfc || (!capabilities.hasFIDO && capabilities.hasSmartCard) ? .ccid : .fido
    }

    private enum USBInterface {
        static let otp: UInt8 = 0x01
        static let fido: UInt8 = 0x02
        static let ccid: UInt8 = 0x04
    }

    public init(transport: DeviceTransport = TwinKitConnectionProvider.environmentTransport) {
        self.deviceTransport = transport
    }

    public func makeSmartCardConnection() async throws -> any SmartCardConnection {
        do {
            return try await TwinKitSmartCardConnection(transport: deviceTransport)
        } catch {
            throw ProviderError.unavailable("TwinKit smart-card connection failed: \(error)")
        }
    }

    public func makeFIDOConnection() async throws -> any FIDOConnection {
        guard deviceTransport != .nfc,
            try liveDescriptor().usbInterfaces & USBInterface.fido != 0
        else {
            throw ProviderError.unsupported("FIDO HID is unavailable over the selected transport")
        }
        do {
            return try await TwinKitFIDOConnection()
        } catch {
            throw ProviderError.unavailable("TwinKit FIDO connection failed: \(error)")
        }
    }

    /// Opens the twin's OTP keyboard HID interface when using a USB transport.
    public func makeOTPConnection() async throws -> any OTPConnection {
        guard deviceTransport != .nfc,
            try liveDescriptor().usbInterfaces & USBInterface.otp != 0
        else {
            throw ProviderError.unsupported("OTP keyboard HID is unavailable over the selected transport")
        }
        do {
            return try await TwinKitOTPConnection()
        } catch {
            throw ProviderError.unavailable("TwinKit OTP connection failed: \(error)")
        }
    }

    /// Power-cycles the twin, as unplugging and replugging a real key would.
    public func waitForReinsertion(timeout: Duration) async throws {
        do {
            try await TwinKitBackend.shared.powerCycle()
        } catch {
            throw ProviderError.unavailable("TwinKit power cycle failed: \(error)")
        }
    }

    public func deviceInfo() async throws -> DeviceInfo {
        let descriptor = try liveDescriptor()
        let (session, connection) = try await managementSession(descriptor: descriptor)
        do {
            let info: DeviceInfo
            do {
                info = try await session.getDeviceInfo()
            } catch ManagementSessionError.featureNotSupported {
                info = try await legacyDeviceInfo(version: session.version, descriptor: descriptor)
            }
            await connection.close(error: nil)
            return info
        } catch {
            await connection.close(error: error)
            throw ProviderError.unavailable("TwinKit device info failed: \(error)")
        }
    }

    private func liveDescriptor() throws -> TwinKitDeviceDescriptor {
        do {
            return try TwinKitBackend.shared.descriptor()
        } catch {
            throw ProviderError.unavailable("TwinKit descriptor failed: \(error)")
        }
    }

    private func managementSession(
        descriptor: TwinKitDeviceDescriptor
    ) async throws -> (Management.Session, any Connection) {
        if deviceTransport == .nfc || descriptor.usbInterfaces & USBInterface.ccid != 0 {
            let connection = try await makeSmartCardConnection()
            do {
                return (try await Management.Session.makeSession(
                    connection: connection,
                    isNFC: deviceTransport == .nfc
                ), connection)
            } catch {
                await connection.close(error: error)
                throw error
            }
        }
        if descriptor.usbInterfaces & USBInterface.otp != 0 {
            let connection = try await makeOTPConnection()
            do {
                return (try await Management.Session.makeSession(connection: connection), connection)
            } catch {
                await connection.close(error: error)
                throw error
            }
        }
        let connection = try await makeFIDOConnection()
        do {
            return (try await Management.Session.makeSession(connection: connection), connection)
        } catch {
            await connection.close(error: error)
            throw error
        }
    }

    private func legacyDeviceInfo(version: Version, descriptor: TwinKitDeviceDescriptor) async throws -> DeviceInfo {
        var usbCapabilities: UInt = 0
        var serialNumber: UInt = 0
        var enabled: [DeviceTransport: UInt] = [:]
        var supported: [DeviceTransport: UInt] = [:]
        if deviceTransport == .usb {
            if descriptor.usbInterfaces & USBInterface.otp != 0 {
                let connection = try await makeOTPConnection()
                do {
                    let session = try await YubiOTP.Session.makeSession(connection: connection)
                    serialNumber = try await session.getSerialNumber()
                    usbCapabilities |= Capability.otp.rawValue
                    await connection.close(error: nil)
                } catch YubiOTP.SessionError.featureNotSupported {
                    await connection.close(error: nil)
                } catch {
                    await connection.close(error: error)
                    throw error
                }
            }
            if descriptor.usbInterfaces & USBInterface.fido != 0 {
                let connection = try await makeFIDOConnection()
                do {
                    let session = try await CTAP2.Session.makeSession(connection: connection)
                    // A successful HID INIT identifies the legacy U2F interface.
                    usbCapabilities |= Capability.u2f.rawValue
                    do {
                        _ = try await session.getInfo()
                        usbCapabilities |= Capability.fido2.rawValue
                    } catch CTAP2.SessionError.featureNotSupported {
                    } catch CTAP2.SessionError.ctapError(.invalidCommand, _) {
                    }
                    await connection.close(error: nil)
                } catch {
                    await connection.close(error: error)
                    throw error
                }
            }
            if descriptor.usbInterfaces & USBInterface.ccid != 0 {
                let discovered = try await smartCardCapabilities()
                if serialNumber == 0 { serialNumber = discovered.serialNumber }
                var smartCardCapabilities = discovered.capabilities
                if descriptor.usbInterfaces & USBInterface.otp == 0 {
                    smartCardCapabilities &= ~Capability.otp.rawValue
                }
                usbCapabilities |= smartCardCapabilities
            }
            enabled[.usb] = usbCapabilities
            supported[.usb] = physicalUSBCapabilities(descriptor: descriptor, observed: usbCapabilities)
        } else {
            let discovered = try await smartCardCapabilities()
            enabled[.nfc] = discovered.capabilities
            supported[.nfc] = UInt(descriptor.nfcCapabilities)
            serialNumber = discovered.serialNumber
        }
        return DeviceInfo(
            serialNumber: serialNumber,
            version: version,
            supportedCapabilities: supported,
            config: DeviceConfig(enabledCapabilities: enabled)
        )
    }

    private func physicalUSBCapabilities(descriptor: TwinKitDeviceDescriptor, observed: UInt) -> UInt {
        switch descriptor.usbProductID {
        case 0x0110...0x0116:
            // NEO's NFC capability mask remains available across USB mode changes.
            return UInt(descriptor.nfcCapabilities) | observed
        case 0x0410:
            return Capability.otp.rawValue | Capability.u2f.rawValue | observed
        default:
            return observed
        }
    }

    private func smartCardCapabilities() async throws -> (capabilities: UInt, serialNumber: UInt) {
        var capabilities: UInt = 0
        var serialNumber: UInt = 0
        let applications: [(aid: [UInt8], capability: Capability)] = [
            ([0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01], .otp),
            ([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01], .oath),
            ([0xA0, 0x00, 0x00, 0x03, 0x08], .piv),
            ([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01], .openPGP),
            ([0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01], .u2f),
            ([0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02], .u2f),
        ]
        for application in applications {
            let connection = try await makeSmartCardConnection()
            do {
                let aid = application.aid
                let response = try await connection.send(data: Data([0x00, 0xA4, 0x04, 0x00, UInt8(aid.count)] + aid))
                guard response.count >= 2 else {
                    throw ProviderError.unavailable("TwinKit SELECT response is too short")
                }
                let status = response.suffix(2)
                if status.elementsEqual([0x90, 0x00]) {
                    capabilities |= application.capability.rawValue
                    if application.capability == .otp {
                        let serialResponse = try await connection.send(data: Data([0x00, 0x01, 0x10, 0x00]))
                        guard serialResponse.count == 6, serialResponse.suffix(2).elementsEqual([0x90, 0x00]) else {
                            throw ProviderError.unavailable("TwinKit OTP serial response is invalid")
                        }
                        serialNumber = serialResponse.prefix(4).reduce(UInt(0)) { $0 << 8 | UInt($1) }
                    }
                } else if !status.elementsEqual([0x6A, 0x82]) && !status.elementsEqual([0x6D, 0x00]) {
                    throw ProviderError.unavailable("TwinKit SELECT returned an unexpected status")
                }
                await connection.close(error: nil)
            } catch {
                await connection.close(error: error)
                throw error
            }
        }
        return (capabilities, serialNumber)
    }
}

private final class TwinKitSmartCardConnection: SmartCardConnection {
    private let channel: TwinKitSmartCardChannel

    required convenience init() async throws(SmartCardConnectionError) {
        try await self.init(transport: .usb)
    }

    init(transport: DeviceTransport) async throws(SmartCardConnectionError) {
        do {
            self.channel = try await TwinKitBackend.shared.openSmartCard(
                transport: transport == .nfc ? .nfc : .usb
            )
        } catch {
            throw .setupFailed("TwinKit is unavailable", error)
        }
    }

    static func makeConnection() async throws(SmartCardConnectionError) -> TwinKitSmartCardConnection {
        try await TwinKitSmartCardConnection()
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        do {
            return try await channel.send(data)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit APDU exchange failed", error)
        }
    }

    func close(error: Error?) async {
        channel.close(error: error)
    }

    func waitUntilClosed() async -> Error? {
        await channel.waitUntilClosed()
    }
}

private final class TwinKitFIDOConnection: FIDOConnection {
    var mtu: Int { channel.mtu }

    private let channel: TwinKitFIDOChannel

    required init() async throws(FIDOConnectionError) {
        do {
            self.channel = try await TwinKitBackend.shared.openFIDO()
        } catch {
            throw .setupFailed("TwinKit is unavailable", error)
        }
    }

    static func makeConnection() async throws(FIDOConnectionError) -> TwinKitFIDOConnection {
        try await TwinKitFIDOConnection()
    }

    func send(_ packet: Data) async throws(FIDOConnectionError) {
        do {
            try await channel.send(packet)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit CTAPHID write failed", error)
        }
    }

    func receive() async throws(FIDOConnectionError) -> Data {
        do {
            return try await channel.receive()
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .receiveFailed("TwinKit CTAPHID read failed", error)
        }
    }

    func close(error: Error?) async {
        channel.close(error: error)
    }

    func waitUntilClosed() async -> Error? {
        await channel.waitUntilClosed()
    }
}

private final class TwinKitOTPConnection: OTPConnection, @unchecked Sendable {
    private let channel: TwinKitKeyboardChannel

    required init() async throws(OTPConnectionError) {
        do {
            self.channel = try await TwinKitBackend.shared.openKeyboard()
        } catch {
            throw .setupFailed("TwinKit is unavailable", error)
        }
    }

    static func makeConnection() async throws(OTPConnectionError) -> TwinKitOTPConnection {
        try await TwinKitOTPConnection()
    }

    func send(_ report: Data) async throws(OTPConnectionError) {
        do {
            try await channel.send(report)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit OTP feature report write failed", error)
        }
    }

    func receive() async throws(OTPConnectionError) -> Data {
        do {
            return try await channel.receive()
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .receiveFailed("TwinKit OTP feature report read failed", error)
        }
    }

    func close(error: Error?) async {
        channel.close(error: error)
    }

    func waitUntilClosed() async -> Error? {
        await channel.waitUntilClosed()
    }
}
