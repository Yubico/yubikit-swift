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

@_spi(YubiInternal) public struct ProviderCapabilities: Sendable {
    /// FIDO HID access, independently of CTAP2 over a smart-card connection.
    public var hasFIDO: Bool
    /// Smart-card access, including the Lightning accessory protocol on iOS.
    public var hasSmartCard: Bool
    public var hasLightning: Bool
    public var supportsSecureChannel: Bool
    public var isVirtual: Bool

    public init(
        hasFIDO: Bool,
        hasOTP: Bool = false,
        hasSmartCard: Bool = true,
        hasLightning: Bool = false,
        supportsSecureChannel: Bool,
        isVirtual: Bool
    ) {
        self.hasFIDO = hasFIDO
        self.hasOTP = hasOTP
        self.hasSmartCard = hasSmartCard
        self.hasLightning = hasLightning
        self.supportsSecureChannel = supportsSecureChannel
        self.isVirtual = isVirtual
    }

    /// Whether the backend exposes the Yubico OTP keyboard HID interface.
    var hasOTP: Bool
}

@_spi(YubiInternal) public enum CTAP2Transport: Sendable, Equatable {
    case ccid
    case fido
}

@_spi(YubiInternal) public enum ProviderError: Error, Sendable {
    case unsupported(String)
    case unavailable(String)
}
