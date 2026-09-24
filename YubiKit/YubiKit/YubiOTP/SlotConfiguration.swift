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

import CryptoKit
import Foundation

// MARK: - Shared options

extension YubiOTP {

    /// Options every slot configuration accepts.
    public struct SlotOptions: Sendable, Equatable {
        /// Serial number readable through the API. Defaults to `true`.
        public var serialAPIVisible: Bool
        /// Serial number exposed in the USB iSerial field. Available on YubiKey 2.2 or later.
        public var serialUSBVisible: Bool
        /// Allow a later `UPDATE` of this configuration. Defaults to `true`.
        public var allowUpdate: Bool
        /// Program the slot dormant; it must be woken by an update before use. Available on YubiKey 2.3
        /// or later.
        public var dormant: Bool
        /// Invert the LED idle state. Available on YubiKey 2.4 or later, except firmware 3.0.
        public var invertLED: Bool
        /// When set for slot 1, block changes to slot 2, even if slot 2 is empty. A slot 2 configuration
        /// that also sets this option can still be changed. Available on YubiKey 2.0 or later.
        public var protectSlot2: Bool

        /// Creates options shared by every slot configuration.
        public init(
            serialAPIVisible: Bool = true,
            serialUSBVisible: Bool = false,
            allowUpdate: Bool = true,
            dormant: Bool = false,
            invertLED: Bool = false,
            protectSlot2: Bool = false
        ) {
            self.serialAPIVisible = serialAPIVisible
            self.serialUSBVisible = serialUSBVisible
            self.allowUpdate = allowUpdate
            self.dormant = dormant
            self.invertLED = invertLED
            self.protectSlot2 = protectSlot2
        }
    }

    /// Options for the slot configurations that type their output on the keyboard.
    public struct KeyboardOptions: Sendable, Equatable {
        /// The approximate added delay between keystrokes in typed output.
        public enum Pacing: Sendable {
            /// No additional delay.
            case none

            /// Approximately 10 milliseconds.
            case tenMilliseconds

            /// Approximately 20 milliseconds.
            case twentyMilliseconds

            /// Approximately 30 milliseconds.
            case thirtyMilliseconds
        }

        /// Append a carriage return after the output. Defaults to `true`.
        public var appendCarriageReturn: Bool
        /// Use the fast trigger when only slot 1 is configured. Defaults to `true`.
        public var fastTrigger: Bool
        /// Delay between keystrokes. Defaults to ``Pacing/none``.
        public var pacing: Pacing
        /// Type digits on the numeric keypad. Available on YubiKey 2.3 or later.
        public var useNumericKeypad: Bool

        /// Creates keyboard-output options.
        public init(
            appendCarriageReturn: Bool = true,
            fastTrigger: Bool = true,
            pacing: Pacing = .none,
            useNumericKeypad: Bool = false
        ) {
            self.appendCarriageReturn = appendCarriageReturn
            self.fastTrigger = fastTrigger
            self.pacing = pacing
            self.useNumericKeypad = useNumericKeypad
        }
    }

    /// Where tabs are inserted in a typed Yubico OTP.
    public struct TabOptions: Sendable, Equatable {
        /// Insert a tab before the first output field.
        public var beforeFirst: Bool

        /// Insert a tab after the first output field.
        public var afterFirst: Bool

        /// Insert a tab after the second output field.
        public var afterSecond: Bool

        /// Creates tab-placement options.
        public init(beforeFirst: Bool = false, afterFirst: Bool = false, afterSecond: Bool = false) {
            self.beforeFirst = beforeFirst
            self.afterFirst = afterFirst
            self.afterSecond = afterSecond
        }
    }

    /// Where half-second delays are inserted in a typed Yubico OTP.
    public struct DelayOptions: Sendable, Equatable {
        /// Pause after the first output field.
        public var afterFirst: Bool

        /// Pause after the second output field.
        public var afterSecond: Bool

        /// Creates delay-placement options.
        public init(afterFirst: Bool = false, afterSecond: Bool = false) {
            self.afterFirst = afterFirst
            self.afterSecond = afterSecond
        }
    }
}

// MARK: - Slot configuration

extension YubiOTP {

    /// A validated configuration for one of the YubiKey's OTP slots.
    public struct SlotConfiguration: Sendable {
        /// The number of digits in an HOTP code.
        public enum Digits: Sendable {
            /// A six-digit code.
            case six

            /// An eight-digit code.
            case eight
        }

        /// How the token identifier preceding an HOTP code is encoded.
        public enum TokenIDEncoding: Sendable {
            /// All bytes contain binary-coded decimal digits.
            case decimal
            /// The first byte uses modhex; the remaining bytes contain binary-coded decimal digits.
            case modhexFirstByte
            /// The first two bytes use modhex; the remaining bytes contain binary-coded decimal digits.
            case modhexFirstTwoBytes
            /// All bytes use modhex.
            case modhex
        }

        /// Creates an HMAC-SHA1 challenge-response configuration for YubiKey 2.2 or later.
        ///
        /// The key may contain up to 20 bytes; keys longer than 64 bytes are hashed down.
        /// Keys of 21 through 64 bytes are rejected.
        ///
        /// - Parameters:
        ///   - key: The HMAC-SHA1 secret.
        ///   - requireTouch: Whether the YubiKey requires a touch to calculate each response.
        ///   - messageUnder64Bytes: Whether challenges can be shorter than 64 bytes. If `false`, all
        ///     challenges must contain exactly 64 bytes. A shorter challenge then gives a different
        ///     response and no error; see ``YubiOTP/Session/calculateHMACSHA1(challenge:in:)``.
        ///   - options: Options shared by every slot configuration.
        public static func hmacSHA1(
            key: Data,
            requireTouch: Bool = false,
            messageUnder64Bytes: Bool = true,
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) -> Self {
            let packed = packHMACKey(try shortenHMACKey(key))
            var flags: ConfigFlags = [.challengeHMAC]
            if messageUnder64Bytes { flags.insert(.hmacLessThan64Bytes) }
            if requireTouch { flags.insert(.challengeButtonTrigger) }
            return Self(
                uid: packed.uid,
                key: packed.key,
                ticketFlags: [.challengeResponse],
                configFlags: flags,
                minimumVersion: Version("2.2.0")!,
                options: options
            )
        }

        /// Creates a Yubico OTP configuration.
        ///
        /// - Parameters:
        ///   - publicID: The static part at the start of each OTP, at most 16 bytes. Use
        ///     ``YubiOTP/Modhex/decode(_:)`` to create it from its modhex form.
        ///   - privateID: The private ID inside the encrypted part of each OTP, exactly 6 bytes.
        ///   - key: The AES key that encrypts each OTP, exactly 16 bytes.
        ///   - tabs: Where to insert tabs in the output.
        ///   - delays: Where to insert delays in the output.
        ///   - sendReference: Whether to send a reference string of all 16 modhex characters before
        ///     the OTP.
        ///   - keyboard: Options for the typed output.
        ///   - options: Options shared by every slot configuration.
        public static func yubicoOTP(
            publicID: Data,
            privateID: Data,
            key: Data,
            tabs: TabOptions = .init(),
            delays: DelayOptions = .init(),
            sendReference: Bool = false,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) -> Self {
            guard publicID.count <= otpFixedSize else {
                throw .illegalArgument("publicID must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard privateID.count == otpUIDSize else {
                throw .illegalArgument("privateID must be exactly \(otpUIDSize) bytes", source: .here())
            }
            guard key.count == otpKeySize else {
                throw .illegalArgument("key must be exactly \(otpKeySize) bytes", source: .here())
            }
            return Self(
                fixed: publicID,
                uid: privateID,
                key: key,
                ticketFlags: tabs.ticketFlags.union(delays.ticketFlags),
                configFlags: sendReference ? [.sendReference] : [],
                keyboard: keyboard,
                options: options
            )
        }

        /// Creates a static password configuration for YubiKey 2.0 or later.
        ///
        /// The password must contain at most 38 HID scan codes, not UTF-8 text. Use scan codes
        /// for the keyboard layout on the receiving computer.
        ///
        /// - Parameters:
        ///   - scanCodes: The password as HID keyboard scan codes.
        ///   - keyboard: Options for the typed output.
        ///   - options: Options shared by every slot configuration.
        public static func staticPassword(
            scanCodes: Data,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) -> Self {
            guard scanCodes.count <= otpScanCodesSize else {
                throw .illegalArgument("Password is too long, at most \(otpScanCodesSize) scan codes", source: .here())
            }
            var padded = scanCodes
            padded.append(Data(count: otpScanCodesSize - scanCodes.count))
            let codes = Array(padded)
            return Self(
                fixed: Data(codes[0..<otpFixedSize]),
                uid: Data(codes[otpFixedSize..<(otpFixedSize + otpUIDSize)]),
                key: Data(codes[(otpFixedSize + otpUIDSize)...]),
                configFlags: [.shortTicket],
                minimumVersion: Version("2.0.0")!,
                keyboard: keyboard,
                options: options
            )
        }

        /// Creates a static ticket configuration.
        ///
        /// This is a legacy format; prefer ``staticPassword(scanCodes:keyboard:options:)`` for static passwords.
        /// A static ticket behaves like a Yubico OTP, but with all changing state removed.
        ///
        /// - Parameters:
        ///   - fixed: The fixed part of the ticket, at most 16 bytes.
        ///   - uid: The UID, which corresponds to a Yubico OTP private ID, exactly 6 bytes.
        ///   - key: The AES key that generates the dynamic part of the ticket, exactly 16 bytes.
        ///   - shortTicket: Whether to truncate the OTP part of the ticket to 16 characters.
        ///   - upperCase: Whether to upper-case the first two letters of the output.
        ///   - digit: Whether to replace the first eight characters of the modhex alphabet with the
        ///     digits 0 to 7.
        ///   - special: Whether to send `!` as the first character. Implies `digit`.
        ///   - manualUpdate: Whether the user can generate a new static ticket by holding the touch
        ///     sensor for 8 to 15 seconds. Supported only on YubiKey 2.x.
        ///   - keyboard: Options for the typed output.
        ///   - options: Options shared by every slot configuration.
        public static func staticTicket(
            fixed: Data,
            uid: Data,
            key: Data,
            shortTicket: Bool = false,
            upperCase: Bool = false,
            digit: Bool = false,
            special: Bool = false,
            manualUpdate: Bool = false,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) -> Self {
            guard fixed.count <= otpFixedSize else {
                throw .illegalArgument("fixed must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard uid.count == otpUIDSize else {
                throw .illegalArgument("uid must be exactly \(otpUIDSize) bytes", source: .here())
            }
            guard key.count == otpKeySize else {
                throw .illegalArgument("key must be exactly \(otpKeySize) bytes", source: .here())
            }
            var flags: ConfigFlags = [.staticTicket]
            if shortTicket { flags.insert(.shortTicket) }
            if upperCase { flags.insert(.strongPassword1) }
            if digit || special { flags.insert(.strongPassword2) }
            if special { flags.insert(.sendReference) }
            if manualUpdate { flags.insert(.manualUpdate) }
            let needsVersion2 = shortTicket || upperCase || digit || special || manualUpdate
            return Self(
                fixed: fixed,
                uid: uid,
                key: key,
                configFlags: flags,
                minimumVersion: needsVersion2 ? Version("2.0.0")! : nil,
                keyboard: keyboard,
                options: options
            )
        }

        /// Creates an OATH-HOTP configuration for YubiKey 2.1 or later.
        ///
        /// The key may contain up to 20 bytes; keys longer than 64 bytes are hashed down.
        /// Keys of 21 through 64 bytes are rejected.
        ///
        /// - Parameters:
        ///   - key: The OATH-HOTP secret.
        ///   - digits: The number of digits in each code.
        ///   - tokenID: The token ID that precedes each code, at most 16 bytes.
        ///   - tokenIDEncoding: How the token ID is encoded in the output.
        ///   - initialCounter: The initial counter value, in `0...1048560` and evenly divisible by 16.
        ///   - keyboard: Options for the typed output.
        ///   - options: Options shared by every slot configuration.
        public static func hotp(
            key: Data,
            digits: Digits = .six,
            tokenID: Data = Data(),
            tokenIDEncoding: TokenIDEncoding = .modhexFirstTwoBytes,
            initialCounter: UInt32 = 0,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) -> Self {
            guard tokenID.count <= otpFixedSize else {
                throw .illegalArgument("tokenID must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard initialCounter % 16 == 0, initialCounter <= 0xFFFF0 else {
                throw .illegalArgument(
                    "initialCounter must be 0...1048560 and evenly divisible by 16",
                    source: .here()
                )
            }
            let packed = packHMACKey(try shortenHMACKey(key))
            var uid = packed.uid
            if initialCounter != 0 {
                let shifted = UInt16(initialCounter >> 4)
                uid = uid.prefix(4) + Data([UInt8(shifted >> 8), UInt8(shifted & 0xFF)])
            }
            var flags = tokenIDEncoding.configFlags
            if digits == .eight { flags.insert(.oathHOTP8) }
            return Self(
                fixed: tokenID,
                uid: uid,
                key: packed.key,
                ticketFlags: [.oathHOTP],
                configFlags: flags,
                minimumVersion: Version("2.1.0")!,
                keyboard: keyboard,
                options: options
            )
        }

        /// Whether YubiKey firmware of the given version supports this configuration.
        ///
        /// - Parameter version: The firmware version to check, for example ``YubiOTP/Session/version``.
        public func isSupported(by version: Version) -> Bool {
            (minimumVersion.map { version >= $0 } ?? true) && options.isSupported(by: version)
                && (keyboard?.isSupported(by: version) ?? true)
        }

        func configData(accessCode: Data?) -> Data {
            buildOTPConfig(
                fixed: fixed,
                uid: uid,
                key: key,
                extendedFlags: extendedFlags,
                ticketFlags: ticketFlags,
                configFlags: configFlags,
                accessCode: accessCode
            )
        }

        private let fixed: Data
        private let uid: Data
        private let key: Data
        private let extendedFlags: ExtendedFlags
        private let ticketFlags: TicketFlags
        private let configFlags: ConfigFlags
        private let minimumVersion: Version?
        private let options: SlotOptions
        private let keyboard: KeyboardOptions?

        private init(
            fixed: Data = Data(),
            uid: Data,
            key: Data,
            ticketFlags: TicketFlags = [],
            configFlags: ConfigFlags = [],
            minimumVersion: Version? = nil,
            keyboard: KeyboardOptions? = nil,
            options: SlotOptions
        ) {
            self.fixed = fixed
            self.uid = uid
            self.key = key
            self.extendedFlags = options.extendedFlags.union(keyboard?.extendedFlags ?? [])
            self.ticketFlags = options.ticketFlags.union(keyboard?.ticketFlags ?? []).union(ticketFlags)
            self.configFlags = (keyboard?.configFlags ?? []).union(configFlags)
            self.minimumVersion = minimumVersion
            self.options = options
            self.keyboard = keyboard
        }
    }

    /// An update to an already-programmed slot, changing only the flags an `UPDATE` may touch.
    ///
    /// This replaces all writable flags; omitted options use their defaults rather than preserving
    /// the existing values. Requires YubiKey 2.3 or later.
    public struct SlotUpdate: Sendable {
        /// Creates an update from the writable slot options.
        ///
        /// - Throws: ``SessionError/illegalArgument(_:source:)`` if `protectSlot2` is enabled;
        ///   firmware does not permit that flag in an update.
        public init(
            tabs: TabOptions = .init(),
            delays: DelayOptions = .init(),
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTP.SessionError) {
            // An update may carry every flag that these options produce, except protectSlot2.
            guard !options.protectSlot2 else {
                throw .illegalArgument("protectSlot2 cannot be applied to an update", source: .here())
            }
            self.tabs = tabs
            self.delays = delays
            self.keyboard = keyboard
            self.options = options
        }

        /// Whether YubiKey firmware of the given version supports this update.
        ///
        /// - Parameter version: The firmware version to check, for example ``YubiOTP/Session/version``.
        public func isSupported(by version: Version) -> Bool {
            YubiOTP.Feature.update.isSupported(by: version) && options.isSupported(by: version)
                && keyboard.isSupported(by: version)
        }

        func configData(accessCode: Data?) -> Data {
            // An update carries no secret: fixed, uid and key are all zero.
            buildOTPConfig(
                fixed: Data(count: otpFixedSize),
                uid: Data(count: otpUIDSize),
                key: Data(count: otpKeySize),
                extendedFlags: options.extendedFlags.union(keyboard.extendedFlags),
                ticketFlags: options.ticketFlags.union(keyboard.ticketFlags)
                    .union(tabs.ticketFlags).union(delays.ticketFlags),
                configFlags: keyboard.configFlags,
                accessCode: accessCode
            )
        }

        private let tabs: TabOptions
        private let delays: DelayOptions
        private let keyboard: KeyboardOptions
        private let options: SlotOptions
    }
}

// MARK: - Configuration Encoding

extension YubiOTP.SlotOptions {
    // The minimum firmware versions that yubikit-android uses. Older firmware ignores SERIAL_API_VISIBLE
    // and ALLOW_UPDATE.
    fileprivate func isSupported(by version: Version) -> Bool {
        (!protectSlot2 || version >= Version("2.0.0")!)
            && (!serialUSBVisible || version >= Version("2.2.0")!)
            && (!dormant || version >= Version("2.3.0")!)
            && (!invertLED || (version >= Version("2.4.0")! && !(version.major == 3 && version.minor == 0)))
    }

    fileprivate var extendedFlags: YubiOTP.ExtendedFlags {
        var flags: YubiOTP.ExtendedFlags = []
        if serialAPIVisible { flags.insert(.serialAPIVisible) }
        if serialUSBVisible { flags.insert(.serialUSBVisible) }
        if allowUpdate { flags.insert(.allowUpdate) }
        if dormant { flags.insert(.dormant) }
        if invertLED { flags.insert(.invertLED) }
        return flags
    }

    fileprivate var ticketFlags: YubiOTP.TicketFlags { protectSlot2 ? [.protectSlot2] : [] }
}

extension YubiOTP.KeyboardOptions {
    fileprivate func isSupported(by version: Version) -> Bool {
        !useNumericKeypad || version >= Version("2.3.0")!
    }

    fileprivate var extendedFlags: YubiOTP.ExtendedFlags {
        var flags: YubiOTP.ExtendedFlags = []
        if fastTrigger { flags.insert(.fastTrigger) }
        if useNumericKeypad { flags.insert(.useNumericKeypad) }
        return flags
    }

    fileprivate var ticketFlags: YubiOTP.TicketFlags {
        appendCarriageReturn ? [.appendCarriageReturn] : []
    }

    fileprivate var configFlags: YubiOTP.ConfigFlags {
        switch pacing {
        case .none: []
        case .tenMilliseconds: [.pacing10ms]
        case .twentyMilliseconds: [.pacing20ms]
        case .thirtyMilliseconds: [.pacing10ms, .pacing20ms]
        }
    }
}

extension YubiOTP.TabOptions {
    fileprivate var ticketFlags: YubiOTP.TicketFlags {
        var flags: YubiOTP.TicketFlags = []
        if beforeFirst { flags.insert(.tabFirst) }
        if afterFirst { flags.insert(.appendTab1) }
        if afterSecond { flags.insert(.appendTab2) }
        return flags
    }
}

extension YubiOTP.DelayOptions {
    fileprivate var ticketFlags: YubiOTP.TicketFlags {
        var flags: YubiOTP.TicketFlags = []
        if afterFirst { flags.insert(.appendDelay1) }
        if afterSecond { flags.insert(.appendDelay2) }
        return flags
    }
}

extension YubiOTP.SlotConfiguration.TokenIDEncoding {
    fileprivate var configFlags: YubiOTP.ConfigFlags {
        switch self {
        case .decimal: []
        case .modhexFirstByte: [.oathFixedModhex1]
        case .modhexFirstTwoBytes: [.oathFixedModhex2]
        case .modhex: [.oathFixedModhex1, .oathFixedModhex2]
        }
    }
}

// MARK: - Wire Format

// Shared with the session, which appends the current access code to every configuration write.
let otpAccessCodeSize = 6
let otpConfigSize = 52

// MARK: - Field sizes

private let otpFixedSize = 16
private let otpUIDSize = 6
private let otpKeySize = 16
private let otpScanCodesSize = otpFixedSize + otpUIDSize + otpKeySize
private let hmacKeySize = 20
private let sha1BlockSize = 64

// MARK: - Flag bits

extension YubiOTP {
    fileprivate struct ExtendedFlags: OptionSet, Sendable {
        let rawValue: UInt8
        static let serialUSBVisible = ExtendedFlags(rawValue: 0x02)
        static let serialAPIVisible = ExtendedFlags(rawValue: 0x04)
        static let useNumericKeypad = ExtendedFlags(rawValue: 0x08)
        static let fastTrigger = ExtendedFlags(rawValue: 0x10)
        static let allowUpdate = ExtendedFlags(rawValue: 0x20)
        static let dormant = ExtendedFlags(rawValue: 0x40)
        static let invertLED = ExtendedFlags(rawValue: 0x80)
    }

    fileprivate struct TicketFlags: OptionSet, Sendable {
        let rawValue: UInt8
        static let tabFirst = TicketFlags(rawValue: 0x01)
        static let appendTab1 = TicketFlags(rawValue: 0x02)
        static let appendTab2 = TicketFlags(rawValue: 0x04)
        static let appendDelay1 = TicketFlags(rawValue: 0x08)
        static let appendDelay2 = TicketFlags(rawValue: 0x10)
        static let appendCarriageReturn = TicketFlags(rawValue: 0x20)
        static let protectSlot2 = TicketFlags(rawValue: 0x80)
        // OATH HOTP mode (YubiKey 2.1+); shares a bit with challengeResponse.
        static let oathHOTP = TicketFlags(rawValue: 0x40)
        // Challenge-response enabled (YubiKey 2.2+).
        static let challengeResponse = TicketFlags(rawValue: 0x40)
    }

    fileprivate struct ConfigFlags: OptionSet, Sendable {
        let rawValue: UInt8
        static let sendReference = ConfigFlags(rawValue: 0x01)
        static let pacing10ms = ConfigFlags(rawValue: 0x04)
        static let pacing20ms = ConfigFlags(rawValue: 0x08)
        static let staticTicket = ConfigFlags(rawValue: 0x20)
        static let shortTicket = ConfigFlags(rawValue: 0x02)
        static let strongPassword1 = ConfigFlags(rawValue: 0x10)
        static let strongPassword2 = ConfigFlags(rawValue: 0x40)
        static let manualUpdate = ConfigFlags(rawValue: 0x80)
        static let oathHOTP8 = ConfigFlags(rawValue: 0x02)
        static let oathFixedModhex1 = ConfigFlags(rawValue: 0x10)
        static let oathFixedModhex2 = ConfigFlags(rawValue: 0x40)
        static let challengeHMAC = ConfigFlags(rawValue: 0x22)
        static let hmacLessThan64Bytes = ConfigFlags(rawValue: 0x04)
        static let challengeButtonTrigger = ConfigFlags(rawValue: 0x08)
    }
}

// Assembles fixed[16] ‖ uid[6] ‖ key[16] ‖ accessCode[6] ‖ fixedLength ‖ flags
// ‖ rfu[2] ‖ crc[2].
private func buildOTPConfig(
    fixed: Data,
    uid: Data,
    key: Data,
    extendedFlags: YubiOTP.ExtendedFlags,
    ticketFlags: YubiOTP.TicketFlags,
    configFlags: YubiOTP.ConfigFlags,
    accessCode: Data?
) -> Data {
    var buffer = Data()
    buffer.append(fixed)
    buffer.append(Data(count: otpFixedSize - fixed.count))
    buffer.append(uid)
    buffer.append(key)
    buffer.append(accessCode ?? Data(count: otpAccessCodeSize))
    buffer.append(contentsOf: [
        UInt8(fixed.count), extendedFlags.rawValue, ticketFlags.rawValue, configFlags.rawValue,
    ])
    buffer.append(Data(count: 2))
    return buffer.appendingCRC16
}

private func shortenHMACKey(_ key: Data) throws(YubiOTP.SessionError) -> Data {
    if key.count > sha1BlockSize {
        return Data(Insecure.SHA1.hash(data: key))
    }
    if key.count > hmacKeySize {
        throw .illegalArgument("HMAC keys longer than \(hmacKeySize) bytes are not supported", source: .here())
    }
    return key
}

private func packHMACKey(_ key: Data) -> (key: Data, uid: Data) {
    var keyField = key.prefix(otpKeySize)
    keyField.append(Data(count: otpKeySize - keyField.count))
    var uidField = key.dropFirst(otpKeySize)
    uidField.append(Data(count: otpUIDSize - uidField.count))
    return (Data(keyField), Data(uidField))
}
