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

    // MARK: - JSON Decoding Tests

    @Suite("JSON Decoding")
    struct JSONDecodingTests {

        @Test("RelyingParty JSON decoding")
        func testRelyingPartyJSON() throws {
            let json = """
                {"id": "example.com", "name": "Example RP"}
                """

            let rp = try JSONDecoder().decode(WebAuthn.RelyingParty.self, from: Data(json.utf8))

            #expect(rp.id == "example.com")
            #expect(rp.name == "Example RP")
        }

        @Test("RelyingParty JSON decoding - no name")
        func testRelyingPartyJSONNoName() throws {
            let json = """
                {"id": "example.com"}
                """

            let rp = try JSONDecoder().decode(WebAuthn.RelyingParty.self, from: Data(json.utf8))

            #expect(rp.id == "example.com")
            #expect(rp.name == nil)
        }

        @Test("User JSON decoding")
        func testUserJSON() throws {
            let json = """
                {"id": "dXNlcl9pZA", "name": "user@example.com", "displayName": "Test User"}
                """

            let user = try JSONDecoder().decode(WebAuthn.User.self, from: Data(json.utf8))

            #expect(user.id == Data("user_id".utf8))
            #expect(user.name == "user@example.com")
            #expect(user.displayName == "Test User")
        }

        @Test("CredentialDescriptor JSON decoding")
        func testCredentialDescriptorJSON() throws {
            let json = """
                {"type": "public-key", "id": "Y3JlZGVudGlhbF9pZA", "transports": ["usb", "nfc"]}
                """

            let descriptor = try JSONDecoder().decode(
                WebAuthn.CredentialDescriptor.self,
                from: Data(json.utf8)
            )

            #expect(descriptor.type == "public-key")
            #expect(descriptor.id == Data("credential_id".utf8))
            #expect(descriptor.transports == [.usb, .nfc])
        }

        @Test("CredentialDescriptor JSON decoding - defaults type to public-key")
        func testCredentialDescriptorJSONDefaultType() throws {
            let json = """
                {"id": "Y3JlZGVudGlhbF9pZA"}
                """

            let descriptor = try JSONDecoder().decode(
                WebAuthn.CredentialDescriptor.self,
                from: Data(json.utf8)
            )

            #expect(descriptor.type == "public-key")
        }

        @Test("Registration.Options JSON decoding")
        func testRegistrationOptionsJSON() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user@example.com", "displayName": "User"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                    "authenticatorSelection": {
                        "residentKey": "required",
                        "userVerification": "required"
                    },
                    "attestation": "direct"
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Registration.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rp.id == "example.com")
            #expect(options.rp.name == "Example")
            #expect(options.user.id == Data("user_id".utf8))
            #expect(options.user.name == "user@example.com")
            #expect(options.pubKeyCredParams == [.es256])
            #expect(options.timeout == .milliseconds(60000))
            #expect(options.residentKey == .required)
            #expect(options.userVerification == .required)
            #expect(options.attestation == .direct)
        }

        @Test("Registration.Options JSON decoding - minimal")
        func testRegistrationOptionsJSONMinimal() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user"}
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Registration.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rp.id == "example.com")
            #expect(options.user.id == Data("user_id".utf8))
            #expect(options.pubKeyCredParams == [.es256, .edDSA, .rs256])
            #expect(options.timeout == nil)
            #expect(options.residentKey == .preferred)
            #expect(options.userVerification == .preferred)
            #expect(options.attestation == .none)
            #expect(options.excludeCredentials.isEmpty)
        }

        @Test("Registration.Options JSON decoding - requireResidentKey fallback")
        func testRegistrationOptionsJSONRequireResidentKey() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user"},
                    "authenticatorSelection": {
                        "requireResidentKey": true
                    }
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Registration.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.residentKey == .required)
        }

        @Test("Registration.Options JSON decoding - with excludeCredentials")
        func testRegistrationOptionsJSONWithExcludeCredentials() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user"},
                    "excludeCredentials": [
                        {"type": "public-key", "id": "Y3JlZDE"},
                        {"type": "public-key", "id": "Y3JlZDI", "transports": ["usb"]}
                    ]
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Registration.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.excludeCredentials.count == 2)
            #expect(options.excludeCredentials[0].id == Data("cred1".utf8))
            #expect(options.excludeCredentials[1].id == Data("cred2".utf8))
            #expect(options.excludeCredentials[1].transports == [.usb])
        }

        @Test("Authentication.Options JSON decoding")
        func testAuthenticationOptionsJSON() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rpId": "example.com",
                    "allowCredentials": [
                        {"type": "public-key", "id": "Y3JlZGVudGlhbF9pZA"}
                    ],
                    "userVerification": "required",
                    "timeout": 30000
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Authentication.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rpId == "example.com")
            #expect(options.allowCredentials.count == 1)
            #expect(options.allowCredentials[0].id == Data("credential_id".utf8))
            #expect(options.userVerification == .required)
            #expect(options.timeout == .milliseconds(30000))
        }

        @Test("Authentication.Options JSON decoding - minimal (discoverable)")
        func testAuthenticationOptionsJSONMinimal() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl"
                }
                """

            let options = try JSONDecoder().decode(
                WebAuthn.Authentication.Options.self,
                from: Data(json.utf8)
            )

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rpId == nil)
            #expect(options.allowCredentials.isEmpty)
            #expect(options.userVerification == .preferred)
            #expect(options.timeout == nil)
        }
    }
}

// MARK: - Helpers

private func randomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
}
