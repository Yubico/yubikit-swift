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

/// Tests for CBOR and JSON serialization of WebAuthn types.
/// Modeled after yubikit-android's SerializationTest.
@Suite("WebAuthn Serialization Tests")
struct SerializationTests {

    // MARK: - CBOR Roundtrip Tests

    @Suite("CBOR Roundtrip")
    struct CBORRoundtripTests {

        @Test("RelyingParty CBOR roundtrip")
        func testRelyingPartyCBOR() throws {
            let rp = WebAuthn.RelyingParty(id: "example.com", name: "Example RP")

            let cbor = rp.cbor()
            let decoded: WebAuthn.RelyingParty = try #require(cbor.cborDecoded())

            #expect(decoded.id == rp.id)
            #expect(decoded.name == rp.name)
        }

        @Test("RelyingParty CBOR roundtrip - no name")
        func testRelyingPartyCBORNoName() throws {
            let rp = WebAuthn.RelyingParty(id: "example.com")

            let cbor = rp.cbor()
            let decoded: WebAuthn.RelyingParty = try #require(cbor.cborDecoded())

            #expect(decoded.id == rp.id)
            #expect(decoded.name == nil)
        }

        @Test("User CBOR roundtrip")
        func testUserCBOR() throws {
            let userId = randomBytes(count: 32)
            let user = WebAuthn.User(id: userId, name: "user@example.com", displayName: "Test User")

            let cbor = user.cbor()
            let decoded: WebAuthn.User = try #require(cbor.cborDecoded())

            #expect(decoded.id == user.id)
            #expect(decoded.name == user.name)
            #expect(decoded.displayName == user.displayName)
        }

        @Test("User CBOR roundtrip - minimal")
        func testUserCBORMinimal() throws {
            let userId = randomBytes(count: 16)
            let user = WebAuthn.User(id: userId)

            let cbor = user.cbor()
            let decoded: WebAuthn.User = try #require(cbor.cborDecoded())

            #expect(decoded.id == user.id)
            #expect(decoded.name == nil)
            #expect(decoded.displayName == nil)
        }

        @Test("CredentialDescriptor CBOR roundtrip")
        func testCredentialDescriptorCBOR() throws {
            let credId = randomBytes(count: 64)
            let descriptor = WebAuthn.CredentialDescriptor(
                id: credId,
                transports: [.usb, .nfc]
            )

            let cbor = descriptor.cbor()
            let decoded: WebAuthn.CredentialDescriptor = try #require(cbor.cborDecoded())

            #expect(decoded.type == descriptor.type)
            #expect(decoded.id == descriptor.id)
            #expect(decoded.transports == descriptor.transports)
        }

        @Test("CredentialDescriptor CBOR roundtrip - no transports")
        func testCredentialDescriptorCBORNoTransports() throws {
            let credId = randomBytes(count: 32)
            let descriptor = WebAuthn.CredentialDescriptor(id: credId)

            let cbor = descriptor.cbor()
            let decoded: WebAuthn.CredentialDescriptor = try #require(cbor.cborDecoded())

            #expect(decoded.type == "public-key")
            #expect(decoded.id == descriptor.id)
            #expect(decoded.transports == nil)
        }
    }
}

// MARK: - Helpers

func randomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
}
