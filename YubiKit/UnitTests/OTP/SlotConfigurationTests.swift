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

/// Byte-exact golden vectors generated from `yubikit.yubiotp` (the wire contract). Every expected
/// value here is the output of the Python reference for the same inputs, so a divergence in any
/// flag bit or field offset fails immediately.
struct SlotConfigurationTests {

    private func config(_ configuration: SlotConfigurationInternal, accessCode: Data? = nil) -> String {
        configuration.configData(accessCode: accessCode).hexEncodedString
    }

    // MARK: - HMAC-SHA1

    @Test("HMACSHA1SlotConfiguration matches the reference bytes for the RFC 2202 key")
    func hmacRFC2202() throws {
        let configuration = try YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x0B, count: 20))
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000024402600007818"
        )
    }

    @Test("a 16-byte HMAC key leaves the uid field empty")
    func hmacShortKey() throws {
        let configuration = try YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x61, count: 16))
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610000000000000024402600002ada"
        )
    }

    @Test("requireTouch sets CHAL_BTN_TRIG")
    func hmacRequireTouch() throws {
        let configuration = try YubiOTP.HMACSHA1SlotConfiguration(
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
        let configuration = try YubiOTP.HMACSHA1SlotConfiguration(
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
        let configuration = try YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x61, count: 16))
        #expect(
            config(configuration, accessCode: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
                == "00000000000000000000000000000000000000000000616161616161616161616161616161610102030405060024402600007d70"
        )
    }

    // MARK: - Yubico OTP

    @Test("YubicoOTPSlotConfiguration matches the reference bytes")
    func yubiOtp() throws {
        let configuration = try YubiOTP.YubicoOTPSlotConfiguration(
            publicId: Data((0x01...0x10)),
            privateId: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F))
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103420000000d413"
        )
    }

    @Test("tabs set TAB_FIRST, APPEND_TAB1 and APPEND_TAB2")
    func yubiOtpTabs() throws {
        let configuration = try YubiOTP.YubicoOTPSlotConfiguration(
            publicId: Data((0x01...0x10)),
            privateId: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            key: Data((0x20...0x2F)),
            tabs: .init(beforeFirst: true, afterFirst: true, afterSecond: true)
        )
        #expect(
            config(configuration)
                == "0102030405060708090a0b0c0d0e0f10111213141516202122232425262728292a2b2c2d2e2f000000000000103427000000f544"
        )
    }

    // MARK: - Static password and ticket

    @Test("StaticPasswordSlotConfiguration packs scan codes across fixed, uid and key")
    func staticPassword() throws {
        let configuration = try YubiOTP.StaticPasswordSlotConfiguration(
            scanCodes: Data([0x04, 0x05, 0x06, 0x07, 0x08])
        )
        #expect(
            config(configuration)
                == "04050607080000000000000000000000000000000000000000000000000000000000000000000000000000001034200200005ed4"
        )
    }

    @Test("StaticTicketSlotConfiguration matches the reference bytes")
    func staticTicket() throws {
        let configuration = try YubiOTP.StaticTicketSlotConfiguration(
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
        let configuration = try YubiOTP.StaticTicketSlotConfiguration(
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

    @Test("HOTPSlotConfiguration matches the reference bytes")
    func hotp() throws {
        let configuration = try YubiOTP.HOTPSlotConfiguration(key: Data(repeating: 0x0B, count: 20))
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000003460400000fff0"
        )
    }

    @Test("digits8 and an initial moving factor are encoded into cfg flags and the uid tail")
    func hotpDigits8AndIMF() throws {
        let configuration = try YubiOTP.HOTPSlotConfiguration(
            key: Data(repeating: 0x0B, count: 20),
            digits8: true,
            initialMovingFactor: 32
        )
        #expect(
            config(configuration)
                == "000000000000000000000000000000000b0b0b0b00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00000000000000346042000034bf"
        )
    }

    @Test("a token id lands in the fixed field and sets its length byte")
    func hotpTokenId() throws {
        let configuration = try YubiOTP.HOTPSlotConfiguration(
            key: Data(repeating: 0x0B, count: 20),
            tokenId: Data([0x01, 0x02, 0x03, 0x04, 0x05])
        )
        #expect(
            config(configuration)
                == "010203040500000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000053460400000b2ae"
        )
    }

    // MARK: - Update

    @Test("UpdateConfiguration carries no secret and only the maskable flags")
    func update() throws {
        let configuration = try YubiOTP.UpdateConfiguration(tabs: .init(beforeFirst: true, afterSecond: true))
        #expect(
            config(configuration)
                == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000001034250000006015"
        )
    }

    // MARK: - Validation

    @Test("an out-of-range initial moving factor is rejected")
    func rejectsBadIMF() {
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.HOTPSlotConfiguration(key: Data(repeating: 0x0B, count: 20), initialMovingFactor: 17)
        }
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.HOTPSlotConfiguration(key: Data(repeating: 0x0B, count: 20), initialMovingFactor: 0x100000)
        }
    }

    @Test("an HMAC key between 20 and 64 bytes cannot be represented")
    func rejectsUnrepresentableKey() {
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x0B, count: 21))
        }
    }

    @Test("an HMAC key longer than the SHA-1 block is hashed down")
    func longKeyIsHashed() throws {
        let long = try YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x0B, count: 65))
        // 20 bytes of digest split across key(16) and uid(4), so the config is still well-formed.
        #expect(long.configData(accessCode: nil).count == otpConfigSize)
    }

    @Test("malformed Yubico OTP identities are rejected")
    func rejectsBadYubiOtpFields() {
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.YubicoOTPSlotConfiguration(
                publicId: Data(),
                privateId: Data(count: 5),
                key: Data(count: 16)
            )
        }
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.YubicoOTPSlotConfiguration(
                publicId: Data(),
                privateId: Data(count: 6),
                key: Data(count: 15)
            )
        }
    }

    @Test("protectSlot2 cannot be applied to an update")
    func rejectsProtectSlot2OnUpdate() {
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.UpdateConfiguration(options: .init(protectSlot2: true))
        }
    }
}
