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

@Suite("WebAuthn Origin Tests")
struct OriginTests {

    @Test(
        "Valid HTTPS origins",
        arguments: [
            ("https://example.com", "https://example.com", "example.com"),
            ("https://example.com:8443", "https://example.com:8443", "example.com"),
            ("https://example.com/path?query=1#fragment", "https://example.com", "example.com"),
        ]
    )
    func testValidHttpsOrigins(input: String, expectedOrigin: String, expectedHost: String) throws {
        let origin = try WebAuthn.Origin(input)
        #expect(origin.stringValue == expectedOrigin)
        #expect(origin.host == expectedHost)
    }

    @Test(
        "Valid localhost origins",
        arguments: [
            "http://localhost",
            "https://localhost",
            "http://localhost:3000",
            "http://LOCALHOST:3000",
            "http://app.localhost:3000",
        ]
    )
    func testValidLocalhostOrigins(origin: String) throws {
        let parsed = try WebAuthn.Origin(origin)
        #expect(parsed.stringValue == origin)
    }

    @Test(
        "Invalid origins",
        arguments: [
            "http://example.com",  // HTTP non-localhost
            "http://127.0.0.1",  // Raw IPv4 loopback not allowed (only "localhost")
            "http://[::1]",  // Raw IPv6 loopback not allowed (only "localhost")
            "not a url",  // Invalid URL
            "example.com",  // Missing scheme
        ]
    )
    func testInvalidOrigins(input: String) {
        #expect(throws: WebAuthn.Origin.Error.self) {
            try WebAuthn.Origin(input)
        }
    }
}
