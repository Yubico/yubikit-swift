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

import CoreNFC
#if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator)
import YubiKitTwinSupport
#endif

/// Real YubiKey provider over NFC.
@_spi(YubiInternal) public struct NFCConnectionProvider: ConnectionProvider {

    /// Whether this backend has an NFC reader, independently of a key being present.
    public static var isAvailable: Bool {
        #if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator)
        return (try? TwinKitBackend.shared.descriptor()) != nil
        #else
        return NFCReaderSession.readingAvailable
        #endif
    }

    public var capabilities: ProviderCapabilities {
        ProviderCapabilities(
            hasFIDO: false,
            hasSmartCard: Self.isAvailable,
            supportsSecureChannel: Self.isAvailable,
            isVirtual: Self.nfcIsVirtual
        )
    }
    public let deviceTransport: DeviceTransport = .nfc
    public let ctap2Transport: CTAP2Transport = .ccid

    private let alertMessage: String?
    private let allowed: [UInt]
    private let infoCache = DeviceInfoCache()

    public init(
        alertMessage: String? = "Hold your YubiKey near the top of the iPhone",
        allowedSerialNumbers: [UInt] = WiredConnectionProvider.allowedSerialNumbers
    ) {
        self.alertMessage = alertMessage
        self.allowed = allowedSerialNumbers
    }

    public func makeSmartCardConnection() async throws -> any SmartCardConnection {
        try Self.requireAvailableReader()
        let connection = try await NFCSmartCardConnection(alertMessage: alertMessage)
        do {
            let info = try await Management.Session.makeSession(connection: connection).getDeviceInfo()
            guard await infoCache.acceptsAndCaches(info, allowed: allowed) else {
                throw ProviderError.unavailable(
                    "The tapped YubiKey (serial \(info.serialNumber)) is not the selected "
                        + "YubiKey, or is not allowed. "
                        + WiredConnectionProvider.allowlistHint
                )
            }
            return connection
        } catch {
            await connection.close(error: nil)
            throw error
        }
    }

    public func makeFIDOConnection() async throws -> any FIDOConnection {
        throw ProviderError.unsupported("NFC has no FIDO/HID transport")
    }

    /// Reads `DeviceInfo` from a tapped YubiKey, ignoring the allow-list.
    ///
    /// This only reads device information, so an app can show which key the user is about to
    /// authorize for destructive scenarios.
    public func identifyTappedYubiKey() async throws -> DeviceInfo {
        try Self.requireAvailableReader()
        let connection = try await NFCSmartCardConnection(alertMessage: alertMessage)
        let info: DeviceInfo
        do {
            info = try await Management.Session.makeSession(connection: connection).getDeviceInfo()
        } catch {
            await connection.close(error: error)
            throw error
        }
        await connection.close(error: nil)
        return try WiredConnectionProvider.authorizable(info)
    }

    /// Over NFC every new session powers the key up from the reader's field, so there is nothing to wait for.
    public func waitForReinsertion(timeout: Duration) async throws {}

    public func deviceInfo() async throws -> DeviceInfo {
        if let cached = await infoCache.value { return cached }
        let connection = try await makeSmartCardConnection()
        await connection.close(error: nil)
        guard let info = await infoCache.value else {
            throw ProviderError.unavailable("Could not read DeviceInfo from the tapped YubiKey.")
        }
        return info
    }

    private static func requireAvailableReader() throws {
        guard isAvailable else { throw ProviderError.unsupported("NFC reading is unavailable on this host") }
        #if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator)
        guard (try TwinKitBackend.shared.descriptor()).nfcCapabilities != 0 else {
            throw ProviderError.unsupported("The selected TwinKit profile has no NFC interface")
        }
        #endif
    }

    #if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator)
    private static let nfcIsVirtual = true
    #else
    private static let nfcIsVirtual = false
    #endif
}

#endif
