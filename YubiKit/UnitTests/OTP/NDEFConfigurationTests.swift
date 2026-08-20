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

/// Golden vectors from `yubikit.yubiotp._build_ndef_config`.
struct NDEFConfigurationTests {

    private func build(_ value: String?, _ type: YubiOTP.NDEFType = .uri) throws -> String {
        try YubiOTP.buildNDEFConfig(value: value, type: type).hexEncodedString
    }

    @Test("the default URI abbreviates its https:// prefix to identifier 4")
    func defaultURI() throws {
        #expect(
            try build(nil)
                == "1355046d792e79756269636f2e636f6d2f796b2f23"
                + String(repeating: "00", count: 35)
        )
    }

    @Test("a https:// URI is abbreviated to identifier 4")
    func httpsURI() throws {
        #expect(
            try build("https://example.com/x")
                == "0e55046578616d706c652e636f6d2f78" + String(repeating: "00", count: 40)
        )
    }

    @Test("a ftp:// URI picks the later table entry, identifier 13")
    func ftpURI() throws {
        #expect(try build("ftp://x") == "02550d78" + String(repeating: "00", count: 52))
    }

    @Test("a text record is prefixed with the language code")
    func textRecord() throws {
        #expect(try build("hello", .text) == "085402656e68656c6c6f" + String(repeating: "00", count: 46))
    }

    @Test("an unknown scheme is written verbatim with identifier 0")
    func unknownScheme() throws {
        let built = try build("gopher://x")
        #expect(built.hasPrefix("0b5500"), "expected length 11, type U, identifier 0 — got \(built.prefix(6))")
    }

    @Test("an oversized payload is rejected")
    func oversized() {
        #expect(throws: YubiOTPSessionError.self) {
            _ = try YubiOTP.buildNDEFConfig(value: String(repeating: "x", count: 60), type: .text)
        }
    }
}
