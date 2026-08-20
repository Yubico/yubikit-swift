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
import YubiKitIntegrationScenarios
import YubiKitTwinSupport

/// Runs integration scenarios against TwinKit's in-process YubiKey.
///
/// A run targets one transport, the way a real session does — you are either plugged in or tapping
/// a card. `YUBIKIT_TWINKIT_TRANSPORT=nfc` switches the whole run to contactless, where CCID is the
/// only path: the FIDO HID interface is USB-only, so CTAP2 falls back to CCID.
public struct TwinKitConnectionProvider: ConnectionProvider {
    public static let environmentConfigurationError: String? =
        TwinKitBackend.environmentProfileConfigurationError ?? transportConfigurationError

    private static let transportEnvironmentKey = "YUBIKIT_TWINKIT_TRANSPORT"

    private static let transportConfigurationError: String? = {
        guard let value = ProcessInfo.processInfo.environment[transportEnvironmentKey]?.lowercased(),
            !value.isEmpty
        else { return nil }
        guard ["usb", "nfc"].contains(value) else {
            return "invalid \(transportEnvironmentKey) '\(value)' (expected usb or nfc)"
        }
        return nil
    }()

    public static var environmentTransport: DeviceTransport {
        ProcessInfo.processInfo.environment[transportEnvironmentKey]?.lowercased() == "nfc" ? .nfc : .usb
    }

    public let capabilities: ProviderCapabilities
    public let deviceTransport: DeviceTransport
    public let ctap2Transport: CTAP2Transport

    private let infoCache = TwinKitDeviceInfoCache()

    public init(transport: DeviceTransport = TwinKitConnectionProvider.environmentTransport) {
        self.deviceTransport = transport
        // Over NFC there is no USB HID at all, so the FIDO interface is absent.
        let isNFC = transport == .nfc
        self.capabilities = ProviderCapabilities(
            hasFIDO: !isNFC,
            supportsSecureChannel: true,
            isVirtual: true
        )
        self.ctap2Transport = isNFC ? .ccid : .fido
    }

    public func makeSmartCardConnection() async throws -> any SmartCardConnection {
        do {
            return try await TwinKitSmartCardConnection(transport: deviceTransport)
        } catch {
            throw ProviderError.unavailable("TwinKit smart-card connection failed: \(error)")
        }
    }

    public func makeFIDOConnection() async throws -> any FIDOConnection {
        guard deviceTransport != .nfc else {
            throw ProviderError.unsupported("FIDO HID is not reachable over NFC")
        }
        do {
            return try await TwinKitFIDOConnection()
        } catch {
            throw ProviderError.unavailable("TwinKit FIDO connection failed: \(error)")
        }
    }

    public func deviceInfo() async throws -> DeviceInfo {
        if let cached = await infoCache.value { return cached }
        let connection = try await makeSmartCardConnection()
        do {
            let session = try await Management.Session.makeSession(connection: connection)
            let info = try await session.getDeviceInfo()
            await connection.close(error: nil)
            await infoCache.store(info)
            return info
        } catch {
            await connection.close(error: error)
            throw ProviderError.unavailable("TwinKit device info failed: \(error)")
        }
    }
}

private final class TwinKitSmartCardConnection: SmartCardConnection, @unchecked Sendable {
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

private final class TwinKitFIDOConnection: FIDOConnection, @unchecked Sendable {
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

private actor TwinKitDeviceInfoCache {
    private(set) var value: DeviceInfo?

    func store(_ info: DeviceInfo) {
        value = info
    }
}
