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

/// The Yubico OTP application on the YubiKey.
///
/// The application holds two independently programmable slots, reachable over the OTP keyboard HID
/// interface and over SmartCard (CCID). Read more on the
/// [Yubico developer website](https://developers.yubico.com/OTP/).
public enum YubiOTP {

    /// One of the YubiKey's two programmable OTP slots.
    public enum Slot: UInt8, Sendable, CaseIterable {
        /// The short-touch slot.
        case one = 1
        /// The long-touch slot.
        case two = 2

        /// Slot command code for writing a configuration.
        var configCommand: UInt8 { self == .one ? 0x01 : 0x03 }
        /// Slot command code for updating a configuration.
        var updateCommand: UInt8 { self == .one ? 0x04 : 0x05 }
        /// Slot command code for writing an NDEF record.
        var ndefCommand: UInt8 { self == .one ? 0x08 : 0x09 }
        /// Slot command code for an HMAC-SHA1 challenge.
        var challengeHMACCommand: UInt8 { self == .one ? 0x30 : 0x38 }
    }

    /// Yubico OTP session features and the firmware versions that introduced them.
    public enum Feature: SessionFeature, Sendable {

        /// Reporting whether a slot is programmed, via ``ConfigState/isConfigured(_:)``.
        case checkConfigured

        /// Reporting whether a programmed slot is triggered by touch, via
        /// ``ConfigState/isTouchTriggered(_:)``.
        case checkTouchTriggered

        /// HMAC-SHA1 challenge-response.
        case challengeResponse

        /// Swapping the two slot configurations.
        case swap

        /// Updating an already-programmed slot.
        case update

        /// Configuring a slot for NDEF output over NFC.
        case ndef

        public func isSupported(by version: Version) -> Bool {
            switch self {
            case .checkConfigured:
                return version >= Version("2.1.0")!
            case .challengeResponse:
                return version >= Version("2.2.0")!
            case .swap, .update:
                return version >= Version("2.3.0")!
            case .checkTouchTriggered, .ndef:
                return version >= Version("3.0.0")!
            }
        }
    }

    /// The configuration state of the two OTP slots.
    ///
    /// Obtained from ``Session/configState``. The underlying bits come from the key's status
    /// struct, so reading the state costs nothing extra.
    public struct ConfigState: Sendable, Equatable, CustomStringConvertible {

        private let flags: UInt16

        init(flags: UInt16) {
            self.flags = flags
        }

        /// Whether the slot is programmed.
        ///
        /// > Note: Requires ``Feature/checkConfigured``, available on YubiKey 2.1 or later. Older
        /// firmware does not report this and will always answer `false`.
        public func isConfigured(_ slot: Slot) -> Bool {
            flags & (slot == .one ? 0x01 : 0x02) != 0
        }

        /// Whether the programmed slot is triggered by touch rather than by challenge-response.
        ///
        /// > Note: Requires ``Feature/checkTouchTriggered``, available on YubiKey 3.0 or later.
        /// Older firmware does not report this and will always answer `false`.
        public func isTouchTriggered(_ slot: Slot) -> Bool {
            flags & (slot == .one ? 0x04 : 0x08) != 0
        }

        /// Whether the LED behaviour is inverted.
        public var isLEDInverted: Bool {
            flags & 0x10 != 0
        }

        public var description: String {
            "ConfigState(configured: (\(isConfigured(.one)), \(isConfigured(.two))), "
                + "touchTriggered: (\(isTouchTriggered(.one)), \(isTouchTriggered(.two))), "
                + "ledInverted: \(isLEDInverted))"
        }
    }
}
