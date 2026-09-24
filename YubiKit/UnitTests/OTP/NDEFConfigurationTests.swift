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

struct NDEFConfigurationTests {

    private func build(_ uri: URL) throws -> String {
        try YubiOTP.buildNDEFConfig(uri: uri).hexEncodedString
    }

    @Test("the default URI abbreviates its https:// prefix to identifier 4")
    func defaultURI() throws {
        #expect(
            try build(YubiOTP.defaultNDEFURI)
                == "1355046d792e79756269636f2e636f6d2f796b2f23"
                + String(repeating: "00", count: 35)
        )
    }

    @Test("a ftp:// URI picks the later table entry, identifier 13")
    func ftpURI() throws {
        #expect(try build(URL(string: "ftp://x")!) == "02550d78" + String(repeating: "00", count: 52))
    }

    @Test("URI encoding preserves percent escapes and the query prefix")
    func preservesURIPrefix() throws {
        let config = try YubiOTP.buildNDEFConfig(uri: URL(string: "https://example.com/a%20b?otp=")!)
        #expect(config.prefix(3) == Data([23, 0x55, 0x04]))
        #expect(config.dropFirst(3).prefix(22) == Data("example.com/a%20b?otp=".utf8))
    }

    @Test("an unknown scheme is written verbatim with identifier 0")
    func unknownScheme() throws {
        let built = try build(URL(string: "gopher://x")!)
        #expect(built.hasPrefix("0b5500"), "expected length 11, type U, identifier 0 — got \(built.prefix(6))")
    }

    @Test("an oversized payload is rejected")
    func oversized() {
        #expect(throws: YubiOTP.SessionError.self) {
            _ = try YubiOTP.buildNDEFConfig(uri: URL(string: "https://" + String(repeating: "x", count: 60))!)
        }
    }
}
