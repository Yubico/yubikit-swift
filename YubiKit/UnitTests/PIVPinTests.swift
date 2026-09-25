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

struct PIVPinTests {

    @Test("padPin returns 8 bytes with the PIN followed by 0xff")
    func testPadPin() throws {
        let padded6 = try PIV.padPin("123456")
        #expect(padded6 == Data([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff]))

        let padded8 = try PIV.padPin("12345678")
        #expect(padded8 == Data([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]))
    }

    @Test("padPin accepts an empty value, as used to exhaust retry counters")
    func testPadEmptyPin() throws {
        let paddedEmpty = try PIV.padPin("")
        #expect(paddedEmpty == Data(repeating: 0xff, count: 8))
    }

    @Test("padPin counts UTF-8 bytes, not characters")
    func testPadPinCountsBytes() throws {
        // "åäö" is 3 characters but 6 UTF-8 bytes.
        let padded = try PIV.padPin("åäö")
        #expect(padded == Data([0xc3, 0xa5, 0xc3, 0xa4, 0xc3, 0xb6, 0xff, 0xff]))
    }

    @Test("padPin rejects a value longer than 8 UTF-8 bytes")
    func testPinTooLong() {
        do {
            _ = try PIV.padPin("123456789")
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .illegalArgument = error else {
                Issue.record("Expected illegalArgument, got \(error)")
                return
            }
        }
    }

    @Test("padPin rejects a value of 8 characters that exceeds 8 UTF-8 bytes")
    func testMultibytePinTooLong() {
        // 8 characters, but 16 UTF-8 bytes.
        do {
            _ = try PIV.padPin("åäöåäöåä")
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .illegalArgument = error else {
                Issue.record("Expected illegalArgument, got \(error)")
                return
            }
        }
    }
}
