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
import Testing

@testable import YubiKit

struct SlotConfigurationTests {

    private func config(_ configuration: YubiOTP.SlotConfiguration, accessCode: Data? = nil) -> String {
        configuration.configData(accessCode: accessCode).hexEncodedString
    }

    private func config(_ update: YubiOTP.SlotUpdate, accessCode: Data? = nil) -> String {
        update.configData(accessCode: accessCode).hexEncodedString
    }

    // MARK: - HMAC-SHA1

    @Test("HMAC-SHA1 matches the reference bytes for the RFC 2202 key")
    func hmacRFC2202() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(repeating: 0x0B, count: 20))
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000024402600007818"
        )
    }

    @Test("a 16-byte HMAC key leaves the uid field empty")
    func hmacShortKey() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(repeating: 0x61, count: 16))
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610000000000000024402600002ada"
        )
    }

    @Test("requireTouch sets CHAL_BTN_TRIG")
    func hmacRequireTouch() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(
            key: Data(repeating: 0x61, count: 16),
            requireTouch: true
        )
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610000000000000024402e0000e81c"
        )
    }

    @Test("clearing messageUnder64Bytes clears HMAC_LT64")
    func hmacNotLessThan64() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(
            key: Data(repeating: 0x61, count: 16),
            messageUnder64Bytes: false
        )
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610000000000000024402200004bb9"
        )
    }

    @Test("an access code is written into the config block")
    func hmacAccessCode() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(repeating: 0x61, count: 16))
        #expect(
            config(configuration, accessCode: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610102030405060024402600007d70"
        )
    }

    // MARK: - Yubico OTP

    @Test("Yubico OTP matches the reference bytes")
    func yubiOtp() throws {
        let configuration = try YubiOTP.SlotConfiguration.yubicoOTP(
            publicID: Data((0x01...0x10)),
            privateID: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F))
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103420000000d413"
        )
    }

    @Test("tabs set TAB_FIRST, APPEND_TAB1 and APPEND_TAB2")
    func yubiOtpTabs() throws {
        let configuration = try YubiOTP.SlotConfiguration.yubicoOTP(
            publicID: Data((0x01...0x10)),
            privateID: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F)),
            tabs: .init(beforeFirst: true, afterFirst: true, afterSecond: true)
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103427000000f544"
        )
    }

    // MARK: - Static password and ticket

    @Test("static password packs scan codes across fixed, uid and key")
    func staticPassword() throws {
        let configuration = try YubiOTP.SlotConfiguration.staticPassword(
            scanCodes: Data([0x04, 0x05, 0x06, 0x07, 0x08])
        )
        #expect(
            config(configuration)
                == "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200200005ed4"
        )
    }

    @Test("static ticket matches the reference bytes")
    func staticTicket() throws {
        let configuration = try YubiOTP.SlotConfiguration.staticTicket(
            fixed: Data((0x01...0x10)),
            uid: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F))
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103420200000ef10"
        )
    }

    @Test("a strong password sets STRONG_PW1, STRONG_PW2 and SEND_REF")
    func staticTicketStrongPassword() throws {
        let configuration = try YubiOTP.SlotConfiguration.staticTicket(
            fixed: Data((0x01...0x10)),
            uid: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F)),
            upperCase: true,
            digit: true,
            special: true
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103420710000d0c9"
        )
    }

    // MARK: - HOTP

    @Test("HOTP matches the reference bytes")
    func hotp() throws {
        let configuration = try YubiOTP.SlotConfiguration.hotp(key: Data(repeating: 0x0B, count: 20))
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000003460400000fff0"
        )
    }

    @Test("eight digits and an initial counter are encoded into cfg flags and the uid tail")
    func hotpEightDigitsAndCounter() throws {
        let configuration = try YubiOTP.SlotConfiguration.hotp(
            key: Data(repeating: 0x0B, count: 20),
            digits: .eight,
            initialCounter: 32
        )
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00000000000000346042000034bf"
        )
    }

    @Test(
        "HOTP token identifier encodings preserve all four flag combinations",
        arguments: [
            (
                .decimal,
                "010203040500000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000053460000000c4a8"
            ),
            (
                .modhexFirstByte,
                "010203040500000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000053460100000512d"
            ),
            (
                .modhexFirstTwoBytes,
                "010203040500000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000053460400000b2ae"
            ),
            (
                .modhex,
                "010203040500000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000053460500000272b"
            ),
        ] as [(YubiOTP.SlotConfiguration.TokenIDEncoding, String)]
    )
    func hotpTokenIDEncoding(_ value: YubiOTP.SlotConfiguration.TokenIDEncoding, expected: String) throws {
        let configuration = try YubiOTP.SlotConfiguration.hotp(
            key: Data(repeating: 0x0B, count: 20),
            tokenID: Data([0x01, 0x02, 0x03, 0x04, 0x05]),
            tokenIDEncoding: value
        )
        #expect(config(configuration) == expected)
    }

    @Test(
        "keyboard pacing preserves all four flag combinations",
        arguments: [
            (
                .none,
                "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200200005ed4"
            ),
            (
                .tenMilliseconds,
                "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200600003fb7"
            ),
            (
                .twentyMilliseconds,
                "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200a00009c12"
            ),
            (
                .thirtyMilliseconds,
                "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200e0000fd71"
            ),
        ] as [(YubiOTP.KeyboardOptions.Pacing, String)]
    )
    func keyboardPacing(_ value: YubiOTP.KeyboardOptions.Pacing, expected: String) throws {
        let configuration = try YubiOTP.SlotConfiguration.staticPassword(
            scanCodes: Data([0x04, 0x05, 0x06, 0x07, 0x08]),
            keyboard: .init(pacing: value)
        )
        #expect(config(configuration) == expected)
    }

    // MARK: - Update

    @Test("SlotUpdate carries no secret and only the maskable flags")
    func update() throws {
        let configuration = try YubiOTP.SlotUpdate(tabs: .init(beforeFirst: true, afterSecond: true))
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000001034250000006015"
        )
    }

    // MARK: - Firmware support

    @Test("configuration families use their enabled flags' firmware requirements")
    func familyFirmwareRequirements() throws {
        let cases: [(YubiOTP.SlotConfiguration, String, String)] = [
            (try YubiOTP.SlotConfiguration.staticPassword(scanCodes: Data()), "1.9.9", "2.0.0"),
            (try YubiOTP.SlotConfiguration.hotp(key: Data()), "2.0.9", "2.1.0"),
            (try YubiOTP.SlotConfiguration.hmacSHA1(key: Data()), "2.1.9", "2.2.0"),
        ]
        for (configuration, before, supported) in cases {
            #expect(!configuration.isSupported(by: Version(before)!))
            #expect(configuration.isSupported(by: Version(supported)!))
        }
    }

    @Test("updates require 2.3 and honor shared options")
    func updateFirmwareRequirements() throws {
        let update = try YubiOTP.SlotUpdate()
        #expect(!update.isSupported(by: Version("2.2.9")!))
        #expect(update.isSupported(by: Version("2.3.0")!))

        let invertedLED = try YubiOTP.SlotUpdate(options: .init(invertLED: true))
        #expect(!invertedLED.isSupported(by: Version("2.3.9")!))
        #expect(invertedLED.isSupported(by: Version("2.4.0")!))
        #expect(!invertedLED.isSupported(by: Version("3.0.0")!))
        #expect(invertedLED.isSupported(by: Version("3.1.0")!))

        let numericKeypad = try YubiOTP.SlotUpdate(keyboard: .init(useNumericKeypad: true))
        #expect(!numericKeypad.isSupported(by: Version("2.2.9")!))
        #expect(numericKeypad.isSupported(by: Version("2.3.0")!))
        #expect(numericKeypad.isSupported(by: Version("5.0.0")!))
    }

    @Test("enabled shared options raise the firmware requirement in every configuration")
    func sharedOptionFirmwareRequirements() throws {
        let cases: [(YubiOTP.SlotOptions, String, String)] = [
            (.init(serialUSBVisible: true), "2.1.9", "2.2.0"),
            (.init(dormant: true), "2.2.9", "2.3.0"),
            (.init(invertLED: true), "2.3.9", "2.4.0"),
            (.init(protectSlot2: true), "1.9.9", "2.0.0"),
        ]
        for (options, before, supported) in cases {
            let configuration = try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 6),
                key: Data(count: 16),
                options: options
            )
            #expect(!configuration.isSupported(by: Version(before)!))
            #expect(configuration.isSupported(by: Version(supported)!))
            #expect(configuration.isSupported(by: Version("5.7.0")!))
        }

        let configurations: [YubiOTP.SlotConfiguration] = [
            try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 6),
                key: Data(count: 16),
                options: .init(invertLED: true)
            ),
            try YubiOTP.SlotConfiguration.staticTicket(
                fixed: Data(),
                uid: Data(count: 6),
                key: Data(count: 16),
                options: .init(invertLED: true)
            ),
            try YubiOTP.SlotConfiguration.staticPassword(scanCodes: Data(), options: .init(invertLED: true)),
            try YubiOTP.SlotConfiguration.hotp(key: Data(), options: .init(invertLED: true)),
            try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(), options: .init(invertLED: true)),
        ]
        for configuration in configurations {
            #expect(!configuration.isSupported(by: Version("2.3.9")!))
            #expect(configuration.isSupported(by: Version("2.4.0")!))
            #expect(!configuration.isSupported(by: Version("3.0.0")!))
            #expect(configuration.isSupported(by: Version("3.1.0")!))
            #expect(configuration.isSupported(by: Version("5.0.0")!))
        }
    }

    @Test("numeric keypad requires 2.3 for every keyboard configuration")
    func numericKeypadFirmwareRequirement() throws {
        let keyboard = YubiOTP.KeyboardOptions(useNumericKeypad: true)
        let configurations: [YubiOTP.SlotConfiguration] = [
            try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 6),
                key: Data(count: 16),
                keyboard: keyboard
            ),
            try YubiOTP.SlotConfiguration.staticTicket(
                fixed: Data(),
                uid: Data(count: 6),
                key: Data(count: 16),
                keyboard: keyboard
            ),
            try YubiOTP.SlotConfiguration.staticPassword(scanCodes: Data(), keyboard: keyboard),
            try YubiOTP.SlotConfiguration.hotp(key: Data(), keyboard: keyboard),
        ]
        for configuration in configurations {
            #expect(!configuration.isSupported(by: Version("2.2.9")!))
            #expect(configuration.isSupported(by: Version("2.3.0")!))
            #expect(configuration.isSupported(by: Version("5.0.0")!))
        }
    }

    @Test("static ticket modifiers require 2.0 only when enabled")
    func staticTicketModifierFirmwareRequirements() throws {
        for index in 0..<5 {
            let configuration = try YubiOTP.SlotConfiguration.staticTicket(
                fixed: Data(),
                uid: Data(count: 6),
                key: Data(count: 16),
                shortTicket: index == 0,
                upperCase: index == 1,
                digit: index == 2,
                special: index == 3,
                manualUpdate: index == 4
            )
            #expect(!configuration.isSupported(by: Version("1.9.9")!))
            #expect(configuration.isSupported(by: Version("2.0.0")!))
            #expect(configuration.isSupported(by: Version("5.0.0")!))
        }
    }

    @Test("non-failing defaults do not prevent programming older firmware")
    func nonFailingDefaults() throws {
        let configurations: [YubiOTP.SlotConfiguration] = [
            try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 6),
                key: Data(count: 16),
                tabs: .init(beforeFirst: true, afterFirst: true, afterSecond: true),
                delays: .init(afterFirst: true, afterSecond: true),
                sendReference: true,
                keyboard: .init(pacing: .thirtyMilliseconds)
            ),
            try YubiOTP.SlotConfiguration.staticTicket(fixed: Data(), uid: Data(count: 6), key: Data(count: 16)),
        ]
        for configuration in configurations {
            #expect(configuration.isSupported(by: Version("1.0.0")!))
        }
    }

    // MARK: - Validation

    @Test("an out-of-range initial counter is rejected")
    func rejectsBadCounter() {
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotConfiguration.hotp(key: Data(repeating: 0x0B, count: 20), initialCounter: 17)
        }
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotConfiguration.hotp(key: Data(repeating: 0x0B, count: 20), initialCounter: 0x100000)
        }
    }

    @Test("an HMAC key between 20 and 64 bytes cannot be represented")
    func rejectsUnrepresentableKey() {
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(repeating: 0x0B, count: 21))
        }
    }

    @Test("an HMAC key that is a slice of a larger buffer packs like a standalone key")
    func hmacKeySlice() throws {
        let key = Data(repeating: 0x0B, count: 20)
        let slice = (Data(repeating: 0xFF, count: 4) + key)[4...]
        #expect(config(try .hmacSHA1(key: slice)) == config(try .hmacSHA1(key: key)))
        #expect(config(try .hotp(key: slice)) == config(try .hotp(key: key)))
    }

    @Test("an HMAC key longer than the SHA-1 block is hashed down")
    func longKeyIsHashed() throws {
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(repeating: 0x0B, count: 65))
        #expect(
            config(configuration)
                == "00000000000000000000000000000000156c50fd00008d9e41b6caf5a7ef181870316228160f0000000000000024402600000ed6"
        )
    }

    @Test("malformed Yubico OTP identities are rejected")
    func rejectsBadYubiOtpFields() {
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 5),
                key: Data(count: 16)
            )
        }
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotConfiguration.yubicoOTP(
                publicID: Data(),
                privateID: Data(count: 6),
                key: Data(count: 15)
            )
        }
    }

    @Test("protectSlot2 cannot be applied to an update")
    func rejectsProtectSlot2OnUpdate() {
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.SlotUpdate(options: .init(protectSlot2: true))
        }
    }
}
