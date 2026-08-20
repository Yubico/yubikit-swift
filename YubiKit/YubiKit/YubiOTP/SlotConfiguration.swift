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

// MARK: - Field sizes

let otpFixedSize = 16
let otpUIDSize = 6
let otpKeySize = 16
let otpAccessCodeSize = 6
let otpConfigSize = 52
let otpScanCodesSize = otpFixedSize + otpUIDSize + otpKeySize  // 38
private let hmacKeySize = 20
private let sha1BlockSize = 64

// MARK: - Flag bits

extension YubiOTP {

    /// Extended flags (`EXTFLAG`).
    struct ExtendedFlags: OptionSet, Sendable {
        let rawValue: UInt8
        static let serialButtonVisible = ExtendedFlags(rawValue: 0x01)
        static let serialUSBVisible = ExtendedFlags(rawValue: 0x02)
        static let serialAPIVisible = ExtendedFlags(rawValue: 0x04)
        static let useNumericKeypad = ExtendedFlags(rawValue: 0x08)
        static let fastTrigger = ExtendedFlags(rawValue: 0x10)
        static let allowUpdate = ExtendedFlags(rawValue: 0x20)
        static let dormant = ExtendedFlags(rawValue: 0x40)
        static let invertLED = ExtendedFlags(rawValue: 0x80)
    }

    /// Ticket flags (`TKTFLAG`).
    struct TicketFlags: OptionSet, Sendable {
        let rawValue: UInt8
        static let tabFirst = TicketFlags(rawValue: 0x01)
        static let appendTab1 = TicketFlags(rawValue: 0x02)
        static let appendTab2 = TicketFlags(rawValue: 0x04)
        static let appendDelay1 = TicketFlags(rawValue: 0x08)
        static let appendDelay2 = TicketFlags(rawValue: 0x10)
        static let appendCarriageReturn = TicketFlags(rawValue: 0x20)
        static let protectSlot2 = TicketFlags(rawValue: 0x80)
        /// OATH HOTP mode (YubiKey 2.1+); shares a bit with ``challengeResponse``.
        static let oathHOTP = TicketFlags(rawValue: 0x40)
        /// Challenge-response enabled (YubiKey 2.2+).
        static let challengeResponse = TicketFlags(rawValue: 0x40)
    }

    /// Configuration flags (`CFGFLAG`).
    struct ConfigFlags: OptionSet, Sendable {
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
        static let challengeYubico = ConfigFlags(rawValue: 0x20)
        static let challengeHMAC = ConfigFlags(rawValue: 0x22)
        static let hmacLessThan64Bytes = ConfigFlags(rawValue: 0x04)
        static let challengeButtonTrigger = ConfigFlags(rawValue: 0x08)
    }
}

// MARK: - Shared options

extension YubiOTP {

    /// Options every slot configuration accepts.
    public struct SlotOptions: Sendable {
        /// Serial number readable through the API. Defaults to `true`.
        public var serialAPIVisible: Bool
        /// Serial number shown at startup on button press.
        public var serialButtonVisible: Bool
        /// Serial number exposed in the USB iSerial field.
        public var serialUSBVisible: Bool
        /// Allow a later `UPDATE` of this configuration. Defaults to `true`.
        public var allowUpdate: Bool
        /// Program the slot dormant; it must be woken by an update before use.
        public var dormant: Bool
        /// Invert the LED idle state.
        public var invertLED: Bool
        /// Block updates of slot 2 unless slot 2 is configured with this bit set.
        public var protectSlot2: Bool

        public init(
            serialAPIVisible: Bool = true,
            serialButtonVisible: Bool = false,
            serialUSBVisible: Bool = false,
            allowUpdate: Bool = true,
            dormant: Bool = false,
            invertLED: Bool = false,
            protectSlot2: Bool = false
        ) {
            self.serialAPIVisible = serialAPIVisible
            self.serialButtonVisible = serialButtonVisible
            self.serialUSBVisible = serialUSBVisible
            self.allowUpdate = allowUpdate
            self.dormant = dormant
            self.invertLED = invertLED
            self.protectSlot2 = protectSlot2
        }

        var extendedFlags: ExtendedFlags {
            var flags: ExtendedFlags = []
            if serialAPIVisible { flags.insert(.serialAPIVisible) }
            if serialButtonVisible { flags.insert(.serialButtonVisible) }
            if serialUSBVisible { flags.insert(.serialUSBVisible) }
            if allowUpdate { flags.insert(.allowUpdate) }
            if dormant { flags.insert(.dormant) }
            if invertLED { flags.insert(.invertLED) }
            return flags
        }

        var ticketFlags: TicketFlags { protectSlot2 ? [.protectSlot2] : [] }
    }

    /// Options for the slot configurations that type their output on the keyboard.
    public struct KeyboardOptions: Sendable {
        /// Append a carriage return after the output. Defaults to `true`.
        public var appendCarriageReturn: Bool
        /// Use the fast trigger when only slot 1 is configured. Defaults to `true`.
        public var fastTrigger: Bool
        /// Add 10 ms of intra-key pacing.
        public var pacing10ms: Bool
        /// Add 20 ms of intra-key pacing.
        public var pacing20ms: Bool
        /// Type digits on the numeric keypad.
        public var useNumericKeypad: Bool

        public init(
            appendCarriageReturn: Bool = true,
            fastTrigger: Bool = true,
            pacing10ms: Bool = false,
            pacing20ms: Bool = false,
            useNumericKeypad: Bool = false
        ) {
            self.appendCarriageReturn = appendCarriageReturn
            self.fastTrigger = fastTrigger
            self.pacing10ms = pacing10ms
            self.pacing20ms = pacing20ms
            self.useNumericKeypad = useNumericKeypad
        }

        var extendedFlags: ExtendedFlags {
            var flags: ExtendedFlags = []
            if fastTrigger { flags.insert(.fastTrigger) }
            if useNumericKeypad { flags.insert(.useNumericKeypad) }
            return flags
        }

        var ticketFlags: TicketFlags { appendCarriageReturn ? [.appendCarriageReturn] : [] }

        var configFlags: ConfigFlags {
            var flags: ConfigFlags = []
            if pacing10ms { flags.insert(.pacing10ms) }
            if pacing20ms { flags.insert(.pacing20ms) }
            return flags
        }
    }

    /// Where tabs are inserted in a typed Yubico OTP.
    public struct TabOptions: Sendable {
        public var beforeFirst: Bool
        public var afterFirst: Bool
        public var afterSecond: Bool

        public init(beforeFirst: Bool = false, afterFirst: Bool = false, afterSecond: Bool = false) {
            self.beforeFirst = beforeFirst
            self.afterFirst = afterFirst
            self.afterSecond = afterSecond
        }

        var ticketFlags: TicketFlags {
            var flags: TicketFlags = []
            if beforeFirst { flags.insert(.tabFirst) }
            if afterFirst { flags.insert(.appendTab1) }
            if afterSecond { flags.insert(.appendTab2) }
            return flags
        }
    }

    /// Where half-second delays are inserted in a typed Yubico OTP.
    public struct DelayOptions: Sendable {
        public var afterFirst: Bool
        public var afterSecond: Bool

        public init(afterFirst: Bool = false, afterSecond: Bool = false) {
            self.afterFirst = afterFirst
            self.afterSecond = afterSecond
        }

        var ticketFlags: TicketFlags {
            var flags: TicketFlags = []
            if afterFirst { flags.insert(.appendDelay1) }
            if afterSecond { flags.insert(.appendDelay2) }
            return flags
        }
    }
}

// MARK: - SlotConfiguration

extension YubiOTP {

    /// A configuration that can be written to one of the YubiKey's OTP slots.
    public protocol SlotConfiguration: Sendable {
        /// Whether the connected YubiKey's firmware supports this configuration.
        func isSupported(by version: Version) -> Bool
    }
}

/// The wire-format half of ``YubiOTP/SlotConfiguration``, kept out of the public surface the way
/// `DeviceConfig.data(reboot:lockCode:newLockCode:)` is.
protocol SlotConfigurationInternal: YubiOTP.SlotConfiguration {
    /// The 52-byte configuration block, CRC included.
    func configData(accessCode: Data?) -> Data
}

extension YubiOTP.SlotConfiguration {
    public func isSupported(by version: Version) -> Bool { true }
}

/// Assembles the 52-byte config block: `fixed[16] ‖ uid[6] ‖ key[16] ‖ accessCode[6] ‖
/// fixedLength ‖ ext ‖ tkt ‖ cfg ‖ rfu[2] ‖ crc[2]`, matching `yubikit.yubiotp._build_config`.
func buildOTPConfig(
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
    buffer.append(Data(count: 2))  // RFU
    return buffer.appendingCRC16
}

/// `_shorten_hmac_key`: keys longer than the SHA-1 block are hashed down; anything between the
/// HMAC key size and the block size cannot be represented in a slot.
func shortenHMACKey(_ key: Data) throws(YubiOTPSessionError) -> Data {
    if key.count > sha1BlockSize {
        return Data(Insecure.SHA1.hash(data: key))
    }
    if key.count > hmacKeySize {
        throw .illegalArgument("HMAC keys longer than \(hmacKeySize) bytes are not supported", source: .here())
    }
    return key
}

/// Splits an HMAC key across the config block's key and uid fields.
private func packHMACKey(_ key: Data) -> (key: Data, uid: Data) {
    var keyField = key.prefix(otpKeySize)
    keyField.append(Data(count: otpKeySize - keyField.count))
    var uidField = key.count > otpKeySize ? key.suffix(from: otpKeySize) : Data()
    uidField.append(Data(count: otpUIDSize - uidField.count))
    return (Data(keyField), Data(uidField))
}

// MARK: - Concrete configurations

extension YubiOTP {

    /// An HMAC-SHA1 challenge-response slot configuration.
    ///
    /// Requires YubiKey 2.2 or later.
    public struct HMACSHA1SlotConfiguration: SlotConfigurationInternal {
        private let key: Data
        private let uid: Data
        private let requireTouch: Bool
        private let messageUnder64Bytes: Bool
        private let options: SlotOptions

        /// - Parameters:
        ///   - key: The HMAC-SHA1 key. Up to 20 bytes; longer than 64 bytes is hashed down.
        ///   - requireTouch: Require a button press before answering a challenge.
        ///   - messageUnder64Bytes: Strip the trailing padding byte from challenges shorter than
        ///     64 bytes. Defaults to `true`.
        public init(
            key: Data,
            requireTouch: Bool = false,
            messageUnder64Bytes: Bool = true,
            options: SlotOptions = .init()
        ) throws(YubiOTPSessionError) {
            let packed = packHMACKey(try shortenHMACKey(key))
            self.key = packed.key
            self.uid = packed.uid
            self.requireTouch = requireTouch
            self.messageUnder64Bytes = messageUnder64Bytes
            self.options = options
        }

        public func isSupported(by version: Version) -> Bool { version >= Version("2.2.0")! }

        func configData(accessCode: Data?) -> Data {
            var config: ConfigFlags = [.challengeHMAC]
            if messageUnder64Bytes { config.insert(.hmacLessThan64Bytes) }
            if requireTouch { config.insert(.challengeButtonTrigger) }
            return buildOTPConfig(
                fixed: Data(),
                uid: uid,
                key: key,
                extendedFlags: options.extendedFlags,
                ticketFlags: options.ticketFlags.union([.challengeResponse]),
                configFlags: config,
                accessCode: accessCode
            )
        }
    }

    /// A Yubico OTP slot configuration.
    public struct YubicoOTPSlotConfiguration: SlotConfigurationInternal {
        private let publicId: Data
        private let privateId: Data
        private let key: Data
        private let tabs: TabOptions
        private let delays: DelayOptions
        private let sendReference: Bool
        private let keyboard: KeyboardOptions
        private let options: SlotOptions

        /// - Parameters:
        ///   - publicId: The public identity, up to 16 bytes.
        ///   - privateId: The private identity, exactly 6 bytes.
        ///   - key: The AES key, exactly 16 bytes.
        ///   - sendReference: Send the reference string `0..F` before the OTP.
        public init(
            publicId: Data,
            privateId: Data,
            key: Data,
            tabs: TabOptions = .init(),
            delays: DelayOptions = .init(),
            sendReference: Bool = false,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTPSessionError) {
            guard publicId.count <= otpFixedSize else {
                throw .illegalArgument("publicId must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard privateId.count == otpUIDSize else {
                throw .illegalArgument("privateId must be exactly \(otpUIDSize) bytes", source: .here())
            }
            guard key.count == otpKeySize else {
                throw .illegalArgument("key must be exactly \(otpKeySize) bytes", source: .here())
            }
            self.publicId = publicId
            self.privateId = privateId
            self.key = key
            self.tabs = tabs
            self.delays = delays
            self.sendReference = sendReference
            self.keyboard = keyboard
            self.options = options
        }

        func configData(accessCode: Data?) -> Data {
            buildOTPConfig(
                fixed: publicId,
                uid: privateId,
                key: key,
                extendedFlags: options.extendedFlags.union(keyboard.extendedFlags),
                ticketFlags: options.ticketFlags.union(keyboard.ticketFlags)
                    .union(tabs.ticketFlags).union(delays.ticketFlags),
                configFlags: keyboard.configFlags.union(sendReference ? [.sendReference] : []),
                accessCode: accessCode
            )
        }
    }

    /// A static password slot configuration, given as HID scan codes.
    ///
    /// Requires YubiKey 2.2 or later.
    public struct StaticPasswordSlotConfiguration: SlotConfigurationInternal {
        private let scanCodes: Data
        private let keyboard: KeyboardOptions
        private let options: SlotOptions

        /// - Parameter scanCodes: The password as HID scan codes, at most 38 bytes.
        public init(
            scanCodes: Data,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTPSessionError) {
            guard scanCodes.count <= otpScanCodesSize else {
                throw .illegalArgument("Password is too long, at most \(otpScanCodesSize) scan codes", source: .here())
            }
            var padded = scanCodes
            padded.append(Data(count: otpScanCodesSize - scanCodes.count))
            self.scanCodes = padded
            self.keyboard = keyboard
            self.options = options
        }

        public func isSupported(by version: Version) -> Bool { version >= Version("2.2.0")! }

        func configData(accessCode: Data?) -> Data {
            // Scan codes are packed across the fixed, uid, and key fields.
            let codes = Array(scanCodes)
            return buildOTPConfig(
                fixed: Data(codes[0..<otpFixedSize]),
                uid: Data(codes[otpFixedSize..<(otpFixedSize + otpUIDSize)]),
                key: Data(codes[(otpFixedSize + otpUIDSize)...]),
                extendedFlags: options.extendedFlags.union(keyboard.extendedFlags),
                ticketFlags: options.ticketFlags.union(keyboard.ticketFlags),
                configFlags: keyboard.configFlags.union([.shortTicket]),
                accessCode: accessCode
            )
        }
    }

    /// A static ticket slot configuration.
    public struct StaticTicketSlotConfiguration: SlotConfigurationInternal {
        private let fixed: Data
        private let uid: Data
        private let key: Data
        private let shortTicket: Bool
        private let upperCase: Bool
        private let digit: Bool
        private let special: Bool
        private let manualUpdate: Bool
        private let keyboard: KeyboardOptions
        private let options: SlotOptions

        public init(
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
        ) throws(YubiOTPSessionError) {
            guard fixed.count <= otpFixedSize else {
                throw .illegalArgument("fixed must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard uid.count == otpUIDSize else {
                throw .illegalArgument("uid must be exactly \(otpUIDSize) bytes", source: .here())
            }
            guard key.count == otpKeySize else {
                throw .illegalArgument("key must be exactly \(otpKeySize) bytes", source: .here())
            }
            self.fixed = fixed
            self.uid = uid
            self.key = key
            self.shortTicket = shortTicket
            self.upperCase = upperCase
            self.digit = digit
            self.special = special
            self.manualUpdate = manualUpdate
            self.keyboard = keyboard
            self.options = options
        }

        func configData(accessCode: Data?) -> Data {
            var config: ConfigFlags = keyboard.configFlags.union([.staticTicket])
            if shortTicket { config.insert(.shortTicket) }
            if upperCase { config.insert(.strongPassword1) }
            if digit || special { config.insert(.strongPassword2) }
            if special { config.insert(.sendReference) }
            return buildOTPConfig(
                fixed: fixed,
                uid: uid,
                key: key,
                extendedFlags: options.extendedFlags.union(keyboard.extendedFlags),
                ticketFlags: options.ticketFlags.union(keyboard.ticketFlags),
                configFlags: manualUpdate ? config.union([.manualUpdate]) : config,
                accessCode: accessCode
            )
        }
    }

    /// An OATH-HOTP slot configuration.
    ///
    /// Requires YubiKey 2.2 or later.
    public struct HOTPSlotConfiguration: SlotConfigurationInternal {
        private let key: Data
        private let uid: Data
        private let tokenId: Data
        private let digits8: Bool
        private let fixedModhex1: Bool
        private let fixedModhex2: Bool
        private let keyboard: KeyboardOptions
        private let options: SlotOptions

        /// - Parameters:
        ///   - key: The HOTP secret. Up to 20 bytes; longer than 64 bytes is hashed down.
        ///   - digits8: Generate 8-digit codes instead of 6.
        ///   - tokenId: Optional token identifier, at most 16 bytes.
        ///   - initialMovingFactor: Starting counter. Must be 0...1048560 and a multiple of 16.
        public init(
            key: Data,
            digits8: Bool = false,
            tokenId: Data = Data(),
            fixedModhex1: Bool = false,
            fixedModhex2: Bool = true,
            initialMovingFactor: UInt32 = 0,
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTPSessionError) {
            guard tokenId.count <= otpFixedSize else {
                throw .illegalArgument("tokenId must be at most \(otpFixedSize) bytes", source: .here())
            }
            guard initialMovingFactor % 16 == 0, initialMovingFactor <= 0xFFFF0 else {
                throw .illegalArgument(
                    "initialMovingFactor must be 0...1048560 and evenly divisible by 16",
                    source: .here()
                )
            }
            let packed = packHMACKey(try shortenHMACKey(key))
            self.key = packed.key
            var uid = packed.uid
            if initialMovingFactor != 0 {
                let shifted = UInt16(initialMovingFactor >> 4)
                uid = uid.prefix(4) + Data([UInt8(shifted >> 8), UInt8(shifted & 0xFF)])
            }
            self.uid = uid
            self.tokenId = tokenId
            self.digits8 = digits8
            self.fixedModhex1 = fixedModhex1
            self.fixedModhex2 = fixedModhex2
            self.keyboard = keyboard
            self.options = options
        }

        public func isSupported(by version: Version) -> Bool { version >= Version("2.2.0")! }

        func configData(accessCode: Data?) -> Data {
            var config = keyboard.configFlags
            if digits8 { config.insert(.oathHOTP8) }
            if fixedModhex1 { config.insert(.oathFixedModhex1) }
            if fixedModhex2 { config.insert(.oathFixedModhex2) }
            return buildOTPConfig(
                fixed: tokenId,
                uid: uid,
                key: key,
                extendedFlags: options.extendedFlags.union(keyboard.extendedFlags),
                ticketFlags: options.ticketFlags.union(keyboard.ticketFlags).union([.oathHOTP]),
                configFlags: config,
                accessCode: accessCode
            )
        }
    }

    /// An update to an already-programmed slot, changing only the flags an `UPDATE` may touch.
    ///
    /// Requires YubiKey 2.2 or later.
    public struct UpdateConfiguration: SlotConfigurationInternal {
        private let tabs: TabOptions
        private let delays: DelayOptions
        private let keyboard: KeyboardOptions
        private let options: SlotOptions

        public init(
            tabs: TabOptions = .init(),
            delays: DelayOptions = .init(),
            keyboard: KeyboardOptions = .init(),
            options: SlotOptions = .init()
        ) throws(YubiOTPSessionError) {
            // Python and Rust mask the flags an UPDATE may carry when building the config block.
            // That check is unreachable here: every flag these four option types can produce is
            // already maskable, leaving `protectSlot2` as the only invalid one. Widening the
            // options this initializer accepts would reintroduce the need for the mask.
            guard !options.protectSlot2 else {
                throw .illegalArgument("protectSlot2 cannot be applied to an update", source: .here())
            }
            self.tabs = tabs
            self.delays = delays
            self.keyboard = keyboard
            self.options = options
        }

        public func isSupported(by version: Version) -> Bool { version >= Version("2.2.0")! }

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
    }
}
