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

    /// A six-byte code that protects the configuration of a slot.
    ///
    /// An all-zero code is the same as no access code. Use `nil` or ``AccessCodeChange/remove`` for an
    /// unprotected slot.
    public struct AccessCode: Sendable, Equatable {
        /// The six bytes of the code.
        public let data: Data

        /// Creates an access code.
        ///
        /// - Parameter data: The code, exactly six bytes and not all zero.
        /// - Throws: ``SessionError/illegalArgument(_:source:)`` if `data` is not six bytes, or if all its
        ///   bytes are zero.
        public init(_ data: Data) throws(YubiOTP.SessionError) {
            guard data.count == otpAccessCodeSize else {
                throw .illegalArgument("Access code must be exactly \(otpAccessCodeSize) bytes", source: .here())
            }
            guard data.contains(where: { $0 != 0 }) else {
                throw .illegalArgument("An all-zero access code is no access code; use nil or .remove", source: .here())
            }
            self.data = Data(data)
        }
    }

    /// How a programming operation changes the slot's access code.
    public enum AccessCodeChange: Sendable {
        /// Preserve protection using the supplied `currentAccessCode`.
        /// Omit the current code only when the slot is unprotected; the key cannot read it back.
        case unchanged

        /// Replace protection with a new code.
        case set(AccessCode)

        /// Remove protection. A protected slot still requires its current code to authorize this.
        case remove
    }

    /// One of the YubiKey's two programmable OTP slots.
    public enum Slot: UInt8, Sendable, CaseIterable {
        /// The short-touch slot.
        case one = 1
        /// The long-touch slot.
        case two = 2
    }

    /// Yubico OTP session features and the firmware versions that introduced them.
    public enum Feature: SessionFeature, Sendable {

        /// Reporting whether a slot is programmed, via ``ConfigState/isConfigured(_:)``.
        case checkConfigured

        /// Reporting whether a programmed slot is triggered by touch, via
        /// ``ConfigState/isTouchTriggered(_:)``.
        case checkTouchTriggered

        /// HMAC-SHA1 challenge-response.
        ///
        /// Only the OTP keyboard HID interface and NFC support this feature. ``Session/supports(_:)``
        /// returns `false` for a USB or Lightning SmartCard session.
        case challengeResponse

        /// Swapping the two slot configurations.
        case swap

        /// Updating an already-programmed slot.
        case update

        /// Configuring a slot for NDEF output over NFC.
        case ndef

        /// Determines whether a firmware version supports the feature.
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
    /// Read it from ``Session/configState``. The YubiKey reports the state with every command, so
    /// reading it sends no command.
    public struct ConfigState: Sendable, Equatable, CustomStringConvertible {
        /// Whether the slot is programmed.
        ///
        /// Over NFC on firmware 5.0.0 through 5.2.4, both slots are reported as configured
        /// because those versions cannot report reliable slot state.
        ///
        /// - Throws: ``SessionError/featureNotSupported(source:)`` on firmware older than
        ///   YubiKey 2.1, which does not report this state.
        public func isConfigured(_ slot: Slot) throws(SessionError) -> Bool {
            guard Feature.checkConfigured.isSupported(by: version) else {
                throw .featureNotSupported(source: .here())
            }
            return configured(slot)
        }

        /// Whether the programmed slot is triggered by touch rather than by challenge-response.
        ///
        /// - Throws: ``SessionError/featureNotSupported(source:)`` on firmware older than
        ///   YubiKey 3.0, which does not report this state.
        public func isTouchTriggered(_ slot: Slot) throws(SessionError) -> Bool {
            guard Feature.checkTouchTriggered.isSupported(by: version) else {
                throw .featureNotSupported(source: .here())
            }
            return touchTriggered(slot)
        }

        /// Whether the LED behaviour is inverted.
        public var isLEDInverted: Bool {
            flags & 0x10 != 0
        }

        /// A textual representation of the reported slot state.
        public var description: String {
            var values = ["ledInverted: \(isLEDInverted)"]
            if Feature.checkTouchTriggered.isSupported(by: version) {
                values.insert("touchTriggered: (\(touchTriggered(.one)), \(touchTriggered(.two)))", at: 0)
            }
            if Feature.checkConfigured.isSupported(by: version) {
                values.insert("configured: (\(configured(.one)), \(configured(.two)))", at: 0)
            }
            return "ConfigState(\(values.joined(separator: ", ")))"
        }

        init(version: Version, flags: UInt8) {
            self.version = version
            self.flags = flags & configStateMask
        }

        private let version: Version
        private let flags: UInt8

        private func configured(_ slot: Slot) -> Bool {
            flags & (slot == .one ? 0x01 : 0x02) != 0
        }

        private func touchTriggered(_ slot: Slot) -> Bool {
            flags & (slot == .one ? 0x04 : 0x08) != 0
        }
    }
}

// MARK: - Slot commands

extension YubiOTP.Slot {
    var configCommand: UInt8 { self == .one ? 0x01 : 0x03 }
    var updateCommand: UInt8 { self == .one ? 0x04 : 0x05 }
    var ndefCommand: UInt8 { self == .one ? 0x08 : 0x09 }
    var challengeHMACCommand: UInt8 { self == .one ? 0x30 : 0x38 }
}

extension YubiOTP {
    static let swapCommand: UInt8 = 0x06
    static let deviceSerialCommand: UInt8 = 0x10
    static let scanMapCommand: UInt8 = 0x12
}

// MARK: - Status struct

// version[3] ‖ programmingSequence[1] ‖ configState[2, LE]
let otpStatusSize = 6
let statusOffsetProgrammingSequence = 3
let statusOffsetConfigState = 4
// The configuration bits of the configuration state; the other bits are the touch level.
let configStateMask: UInt8 = 0x1F
