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

/// Real YubiKey provider over NFC.
public struct NFCConnectionProvider: ConnectionProvider {

    public let capabilities = ProviderCapabilities(
        hasFIDO: false,
        supportsSecureChannel: true,
        isVirtual: nfcIsVirtual
    )
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
        let connection = try await NFCSmartCardConnection(alertMessage: alertMessage)
        do {
            let info = try await Management.Session.makeSession(connection: connection).getDeviceInfo()
            guard await infoCache.acceptsAndCaches(info, allowed: allowed) else {
                throw ProviderError.unavailable(
                    "The tapped YubiKey (serial \(info.serialNumber)) is not the selected "
                        + "YubiKey, or is not in YUBIKEY_TEST_SERIALS."
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

    public func deviceInfo() async throws -> DeviceInfo {
        if let cached = await infoCache.value { return cached }
        let connection = try await makeSmartCardConnection()
        await connection.close(error: nil)
        guard let info = await infoCache.value else {
            throw ProviderError.unavailable("Could not read DeviceInfo from the tapped YubiKey.")
        }
        return info
    }

    #if DEBUG && targetEnvironment(simulator)
    private static let nfcIsVirtual = true
    #else
    private static let nfcIsVirtual = false
    #endif
}

#endif
