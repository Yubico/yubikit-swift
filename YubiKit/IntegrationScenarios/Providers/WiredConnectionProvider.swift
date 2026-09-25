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

#if os(iOS)
import ExternalAccessory
#endif

/// Real YubiKey provider over USB SmartCard, Lightning SmartCard, and macOS FIDO HID.
@_spi(YubiInternal) public struct WiredConnectionProvider: ConnectionProvider {

    /// Decimal serials from `YUBIKEY_TEST_SERIALS` (comma- or space-separated),
    /// plus the simulator backend's fixed serial on simulator builds.
    public static let allowedSerialNumbers: [UInt] =
        ((try? serialConfiguration.get()) ?? []) + simulatorSerialNumbers

    /// How to allow a YubiKey that the serial allowlist rejected.
    static let allowlistHint =
        "Add its serial to YUBIKEY_TEST_SERIALS, or authorize it in the IntegrationTesting app "
        + "(More → Authorize test key…)."

    static let serialConfiguration = parseSerials(
        ProcessInfo.processInfo.environment["YUBIKEY_TEST_SERIALS"]
    )

    static func parseSerials(_ raw: String?) -> Result<[UInt], SerialConfigurationError> {
        guard let raw else { return .success([]) }
        guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .failure(.empty)
        }

        var serials: [UInt] = []
        for group in raw.split(separator: ",", omittingEmptySubsequences: false) {
            let tokens = group.split(whereSeparator: { $0.isWhitespace })
            guard !tokens.isEmpty else { return .failure(.invalidToken(String(group))) }
            for token in tokens {
                guard token.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), let serial = UInt(token), serial > 0 else {
                    return .failure(.invalidToken(String(token)))
                }
                serials.append(serial)
            }
        }
        return .success(serials)
    }

    public let capabilities = ProviderCapabilities(
        hasFIDO: wiredHasFIDO,
        hasOTP: wiredHasOTP,
        supportsSecureChannel: true,
        isVirtual: wiredIsVirtual
    )
    public let deviceTransport: DeviceTransport = .usb
    public let ctap2Transport: CTAP2Transport = wiredCTAP2Transport

    private let allowed: [UInt]
    private let infoCache = DeviceInfoCache()

    public init(allowedSerialNumbers: [UInt] = WiredConnectionProvider.allowedSerialNumbers) {
        self.allowed = allowedSerialNumbers
    }

    public func makeSmartCardConnection() async throws -> any SmartCardConnection {
        if let connection = await vettedUSBConnection() { return connection }

        #if os(iOS)
        if await LightningProbe.hasConnectedYubiKey, let connection = try? await vettedLightningConnection() {
            return connection
        }
        let transports = "USB or Lightning"
        #else
        let transports = "USB"
        #endif

        throw ProviderError.unavailable(
            "No allowed YubiKey found over \(transports). \(Self.allowlistHint)"
        )
    }

    private func vet(_ connection: any SmartCardConnection) async -> (any SmartCardConnection)? {
        do {
            let session = try await Management.Session.makeSession(connection: connection)
            let info = try await session.getDeviceInfo()
            if await infoCache.acceptsAndCaches(info, allowed: allowed) {
                return connection
            }
        } catch {}
        return nil
    }

    private func vet(_ connection: any FIDOConnection) async -> (any FIDOConnection)? {
        do {
            let session = try await Management.Session.makeSession(connection: connection)
            let info = try await session.getDeviceInfo()
            if await infoCache.acceptsAndCaches(info, allowed: allowed) {
                return connection
            }
        } catch {}
        return nil
    }

    private func vettedUSBConnection() async -> (any SmartCardConnection)? {
        guard let slots = try? await USBSmartCardConnection.availableDevices() else { return nil }
        for slot in slots {
            guard let connection = try? await USBSmartCardConnection(slot: slot) else { continue }
            if let vetted = await vet(connection) { return vetted }
            await connection.close(error: nil)
        }
        return nil
    }

    #if os(iOS)
    private func vettedLightningConnection() async throws -> (any SmartCardConnection)? {
        let connection = try await LightningSmartCardConnection()
        if let vetted = await vet(connection) { return vetted }
        await connection.close(error: nil)
        return nil
    }
    #endif

    public func makeFIDOConnection() async throws -> any FIDOConnection {
        #if os(macOS)
        guard let devices = try? await HIDFIDOConnection.availableDevices() else {
            throw ProviderError.unavailable("No FIDO HID devices found.")
        }
        for device in devices {
            guard let connection = try? await HIDFIDOConnection.makeConnection(device: device) else { continue }
            if let vetted = await vet(connection) { return vetted }
            await connection.close(error: nil)
        }
        throw ProviderError.unavailable(
            "No allowed YubiKey found over USB HID. \(Self.allowlistHint)"
        )
        #else
        throw ProviderError.unsupported("FIDO HID is only available on macOS")
        #endif
    }

    /// Opens the OTP keyboard HID interface on an allowed USB YubiKey.
    public func makeOTPConnection() async throws -> any OTPConnection {
        #if os(macOS)
        guard let devices = try? await HIDOTPConnection.availableDevices(), !devices.isEmpty else {
            throw ProviderError.unavailable(
                "No YubiKey exposes an OTP keyboard interface. Enable it with `ykman config usb --enable OTP`."
            )
        }
        for device in devices {
            guard let connection = try? await HIDOTPConnection.makeConnection(device: device) else { continue }
            if await vet(connection) { return connection }
            await connection.close(error: nil)
        }
        throw ProviderError.unavailable(
            "No allowed YubiKey found over the OTP interface. \(Self.allowlistHint)"
        )
        #else
        throw ProviderError.unsupported("The OTP keyboard interface is only available on macOS")
        #endif
    }

    // OTP exposes only a serial number, so check it against the allow-list and pinned device.
    private func vet(_ connection: any OTPConnection) async -> Bool {
        do {
            let session = try await YubiOTP.Session.makeSession(connection: connection)
            let serial = try await session.getSerialNumber()
            if let pinned = await infoCache.value { return pinned.serialNumber == serial }
            return allowed.contains(serial)
        } catch {
            return false
        }
    }

    /// Polls until no YubiKey is attached, then until one is attached again.
    public func waitForReinsertion(timeout: Duration) async throws {
        try await waitForKey(present: false, timeout: timeout, action: "unplugged")
        try await waitForKey(present: true, timeout: timeout, action: "plugged back in")
        // Give the OS a moment to enumerate every interface of the reinserted key.
        try await Task.sleep(for: .milliseconds(500))
    }

    private func waitForKey(present: Bool, timeout: Duration, action: String) async throws {
        let deadline = ContinuousClock.now + timeout
        while await Self.isKeyAttached() != present {
            guard ContinuousClock.now < deadline else {
                throw ProviderError.unavailable("The YubiKey was not \(action) within \(timeout).")
            }
            try await Task.sleep(for: .milliseconds(250))
        }
    }

    private static func isKeyAttached() async -> Bool {
        if let slots = try? await USBSmartCardConnection.availableDevices(), !slots.isEmpty { return true }
        #if os(macOS)
        if let devices = try? await HIDFIDOConnection.availableDevices(), !devices.isEmpty { return true }
        if let devices = try? await HIDOTPConnection.availableDevices(), !devices.isEmpty { return true }
        #endif
        #if os(iOS)
        if await LightningProbe.hasConnectedYubiKey { return true }
        #endif
        return false
    }

    public func deviceInfo() async throws -> DeviceInfo {
        if let cached = await infoCache.value { return cached }
        let connection = try await makeSmartCardConnection()
        await connection.close(error: nil)
        guard let info = await infoCache.value else {
            throw ProviderError.unavailable("Could not read DeviceInfo from the connected YubiKey.")
        }
        return info
    }

    // MARK: - Identification

    /// Reads `DeviceInfo` from the one YubiKey connected over USB or Lightning, ignoring the allow-list.
    ///
    /// This only reads device information, so an app can show which key the user is about to
    /// authorize for destructive scenarios. It fails when no key, or more than one key, is connected.
    public static func identifyConnectedYubiKey() async throws -> DeviceInfo {
        var found: [UInt: DeviceInfo] = [:]

        if let slots = try? await USBSmartCardConnection.availableDevices() {
            for slot in slots {
                guard let connection = try? await USBSmartCardConnection(slot: slot) else { continue }
                if let info = try? await Management.Session.makeSession(connection: connection).getDeviceInfo() {
                    found[info.serialNumber] = info
                }
                await connection.close(error: nil)
            }
        }

        #if os(iOS)
        if found.isEmpty, await LightningProbe.hasConnectedYubiKey,
            let connection = try? await LightningSmartCardConnection()
        {
            if let info = try? await Management.Session.makeSession(connection: connection).getDeviceInfo() {
                found[info.serialNumber] = info
            }
            await connection.close(error: nil)
        }
        let transports = "USB or Lightning"
        #else
        let transports = "USB"
        #endif

        #if os(macOS)
        if found.isEmpty, let devices = try? await HIDFIDOConnection.availableDevices() {
            for device in devices {
                guard let connection = try? await HIDFIDOConnection.makeConnection(device: device) else { continue }
                if let info = try? await Management.Session.makeSession(connection: connection).getDeviceInfo() {
                    found[info.serialNumber] = info
                }
                await connection.close(error: nil)
            }
        }
        #endif

        guard !found.isEmpty else {
            throw ProviderError.unavailable("No YubiKey found over \(transports).")
        }
        guard found.count == 1, let info = found.values.first else {
            throw ProviderError.unavailable(
                "More than one YubiKey is connected. Connect only the YubiKey you want to authorize."
            )
        }
        return try authorizable(info)
    }

    static func authorizable(_ info: DeviceInfo) throws -> DeviceInfo {
        guard info.serialNumber > 0 else {
            throw ProviderError.unavailable("This YubiKey does not report a serial number, so it cannot be authorized.")
        }
        return info
    }

    public func lightningKeyConnected() async -> Bool {
        #if os(iOS)
        return await LightningProbe.hasConnectedYubiKey
        #else
        return false
        #endif
    }

    #if os(macOS)
    private static let wiredHasFIDO = true
    private static let wiredHasOTP = true
    private static let wiredCTAP2Transport: CTAP2Transport = .fido
    #else
    private static let wiredHasFIDO = false
    // iOS has no HID access at all, so the OTP keyboard interface is unreachable there.
    private static let wiredHasOTP = false
    private static let wiredCTAP2Transport: CTAP2Transport = .ccid
    #endif

    #if DEBUG && targetEnvironment(simulator)
    private static let wiredIsVirtual = true
    // The simulator backend reports this fixed serial, so simulator runs do not
    // require YUBIKEY_TEST_SERIALS.
    private static let simulatorSerialNumbers: [UInt] = [12_345_678]
    #else
    private static let wiredIsVirtual = false
    private static let simulatorSerialNumbers: [UInt] = []
    #endif
}

actor DeviceInfoCache {
    private var stored: DeviceInfo?
    var value: DeviceInfo? { stored }
    func acceptsAndCaches(_ info: DeviceInfo, allowed: [UInt]) -> Bool {
        if let stored {
            return info.serialNumber == stored.serialNumber
        }
        guard allowed.contains(info.serialNumber) else {
            return false
        }
        stored = info
        return true
    }
}

enum SerialConfigurationError: Error, Sendable, Equatable, CustomStringConvertible {
    case empty
    case invalidToken(String)

    var description: String {
        switch self {
        case .empty:
            return "YUBIKEY_TEST_SERIALS must contain at least one positive decimal serial"
        case .invalidToken(let token):
            let shown = token.isEmpty ? "<empty>" : token
            return "invalid YubiKey serial '\(shown)' in YUBIKEY_TEST_SERIALS"
        }
    }
}

#if os(iOS)
private enum LightningProbe {
    @MainActor static var hasConnectedYubiKey: Bool {
        EAAccessoryManager.shared().connectedAccessories.contains {
            $0.protocolStrings.contains("com.yubico.ylp") && $0.manufacturer == "Yubico"
        }
    }
}
#endif
