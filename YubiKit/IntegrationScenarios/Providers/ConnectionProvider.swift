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

public protocol ConnectionProvider: Sendable {

    var capabilities: ProviderCapabilities { get }

    var deviceTransport: DeviceTransport { get }

    var ctap2Transport: CTAP2Transport { get }

    func makeSmartCardConnection() async throws -> any SmartCardConnection

    func makeFIDOConnection() async throws -> any FIDOConnection

    func makeOTPConnection() async throws -> any OTPConnection

    func deviceInfo() async throws -> DeviceInfo

    func lightningKeyConnected() async -> Bool
}

extension ConnectionProvider {
    public func lightningKeyConnected() async -> Bool { false }

    public func makeOTPConnection() async throws -> any OTPConnection {
        throw ProviderError.unsupported("OTP (keyboard HID) is not available on this backend")
    }
}

public struct ProviderCapabilities: Sendable {
    public var hasFIDO: Bool
    /// Whether the backend exposes the Yubico OTP keyboard HID interface.
    public var hasOTP: Bool
    public var hasLightning: Bool
    public var supportsSecureChannel: Bool
    public var isVirtual: Bool

    public init(
        hasFIDO: Bool,
        hasOTP: Bool = false,
        hasLightning: Bool = false,
        supportsSecureChannel: Bool,
        isVirtual: Bool
    ) {
        self.hasFIDO = hasFIDO
        self.hasOTP = hasOTP
        self.hasLightning = hasLightning
        self.supportsSecureChannel = supportsSecureChannel
        self.isVirtual = isVirtual
    }
}

public enum CTAP2Transport: Sendable, Equatable {
    case ccid
    case fido
}

public enum ProviderError: Error, Sendable {
    case unsupported(String)
    case unavailable(String)
}
