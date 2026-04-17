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

// MARK: - Test Helpers

/// Builds minimal authenticator data for testing JSON encoding.
/// The actual bytes don't matter - we just need valid objects to encode.
private func makeMinimalAuthData(withAttestedCredential: Bool = false) -> WebAuthn.AuthenticatorData {
    var data = Data(repeating: 0, count: 32)  // rpIdHash
    data.append(withAttestedCredential ? 0x45 : 0x05)  // flags: UP+UV or UP+UV+AT
    data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount

    if withAttestedCredential {
        data.append(Data(repeating: 0, count: 16))  // aaguid
        data.append(contentsOf: [0x00, 0x04])  // credentialId length = 4
        data.append(contentsOf: [0x01, 0x02, 0x03, 0x04])  // credentialId
        // Minimal ES256 COSE key
        data.append(
            contentsOf: [
                0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
                0x21, 0x58, 0x20,
            ] + [UInt8](repeating: 0x01, count: 32) + [  // x
                0x22, 0x58, 0x20,
            ] + [UInt8](repeating: 0x02, count: 32)
        )  // y
    }

    return WebAuthn.AuthenticatorData(data: data)!
}

// MARK: - JSON Tests

extension SerializationTests {

    // MARK: - JSON Decoding

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

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))

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

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rp.id == "example.com")
            #expect(options.user.id == Data("user_id".utf8))
            #expect(options.pubKeyCredParams == [.es256, .edDSA, .rs256])
            #expect(options.timeout == nil)
            #expect(options.residentKey == .discouraged)
            #expect(options.userVerification == .preferred)
            #expect(options.attestation == .none)
            #expect(options.excludeCredentials.isEmpty)
        }

        @Test("Registration.Options JSON decoding - {\"publicKey\": {...}} envelope")
        func testRegistrationOptionsJSONPublicKeyEnvelope() throws {
            let json = """
                {
                    "publicKey": {
                        "challenge": "Y2hhbGxlbmdl",
                        "rp": {"id": "example.com", "name": "Example"},
                        "user": {"id": "dXNlcl9pZA", "name": "user"}
                    }
                }
                """

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))
            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rp.id == "example.com")
            #expect(options.user.id == Data("user_id".utf8))
        }

        @Test("Registration.Options JSON decoding - envelope inner DecodingError is preserved")
        func testRegistrationOptionsJSONEnvelopeInnerError() throws {
            // Envelope shape is valid; inner publicKey is missing required `challenge`.
            // The inner DecodingError must surface, not a vague "envelope failed".
            let json = """
                {"publicKey": {"rp": {"id": "example.com"}}}
                """

            #expect(throws: DecodingError.self) {
                try WebAuthn.Registration.Options.from(json: Data(json.utf8))
            }
        }

        @Test("Registration.Options JSON decoding - thirdPartyPayment (payment) extension")
        func testRegistrationOptionsJSONThirdPartyPayment() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user"},
                    "extensions": {"payment": {"isPayment": true}}
                }
                """

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))
            #expect(options.extensions?.thirdPartyPayment?.isPayment == true)
        }

        @Test("Authentication.Options JSON decoding - thirdPartyPayment ignores SPC metadata")
        func testAuthenticationOptionsJSONThirdPartyPayment() throws {
            // RP servers may send the full SPC dictionary; decoding must accept the extra fields.
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rpId": "example.com",
                    "extensions": {
                        "payment": {
                            "isPayment": true,
                            "rpId": "example.com",
                            "topOrigin": "https://shop.example",
                            "payeeName": "Example Shop",
                            "payeeOrigin": "https://shop.example",
                            "total": {"currency": "USD", "value": "10.00"},
                            "instrument": {
                                "displayName": "Visa card",
                                "icon": "https://example.com/icon.png"
                            }
                        }
                    }
                }
                """

            let options = try WebAuthn.Authentication.Options.from(json: Data(json.utf8))
            let payment = try #require(options.extensions?.thirdPartyPayment)
            #expect(payment.isPayment == true)
        }

        @Test("Registration.Options JSON decoding - thirdPartyPayment isPayment:false decodes to false")
        func testRegistrationOptionsJSONThirdPartyPaymentFalse() throws {
            let json = """
                {
                    "challenge": "Y2hhbGxlbmdl",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"id": "dXNlcl9pZA", "name": "user"},
                    "extensions": {"payment": {"isPayment": false}}
                }
                """

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))
            let payment = try #require(options.extensions?.thirdPartyPayment)
            #expect(payment.isPayment == false)
        }

        @Test("Authentication.Options JSON decoding - {\"publicKey\": {...}} envelope")
        func testAuthenticationOptionsJSONPublicKeyEnvelope() throws {
            let json = """
                {
                    "publicKey": {
                        "challenge": "Y2hhbGxlbmdl",
                        "rpId": "example.com"
                    }
                }
                """

            let options = try WebAuthn.Authentication.Options.from(json: Data(json.utf8))
            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rpId == "example.com")
        }

        @Test("Authentication.Options JSON decoding - envelope tolerates siblings (mediation)")
        func testAuthenticationOptionsJSONEnvelopeWithSiblings() throws {
            let json = """
                {
                    "publicKey": {
                        "challenge": "Y2hhbGxlbmdl",
                        "rpId": "example.com"
                    },
                    "mediation": "conditional"
                }
                """

            let options = try WebAuthn.Authentication.Options.from(json: Data(json.utf8))
            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rpId == "example.com")
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

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))

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

            let options = try WebAuthn.Registration.Options.from(json: Data(json.utf8))

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

            let options = try WebAuthn.Authentication.Options.from(json: Data(json.utf8))

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

            let options = try WebAuthn.Authentication.Options.from(json: Data(json.utf8))

            #expect(options.challenge == Data("challenge".utf8))
            #expect(options.rpId == nil)
            #expect(options.allowCredentials.isEmpty)
            #expect(options.userVerification == .preferred)
            #expect(options.timeout == nil)
        }
    }

    // MARK: - JSON Encoding

    @Suite("JSON Encoding")
    struct JSONEncodingTests {

        @Test("Registration.Response JSON encoding")
        func testRegistrationResponseJSON() throws {
            let authData = makeMinimalAuthData(withAttestedCredential: true)
            let credentialId = authData.attestedCredentialData!.credentialId

            let response = WebAuthn.Registration.Response(
                credentialId: credentialId,
                rawAttestationObject: Data("attestation".utf8),
                rawAuthenticatorData: authData.rawData,
                attestationStatement: .none,
                transports: [.usb],
                clientExtensionResults: .init(),
                publicKey: authData.attestedCredentialData!.credentialPublicKey,
                aaguid: authData.attestedCredentialData!.aaguid,
                signCount: authData.signCount,
                authenticatorData: authData,
                clientDataJSON: Data("clientdata".utf8)
            )

            let encoded = try response.toJSON()
            let json = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

            // Verify envelope fields
            #expect(json["id"] as? String == credentialId.base64URLEncodedString())
            #expect(json["rawId"] as? String == credentialId.base64URLEncodedString())
            #expect(json["type"] as? String == "public-key")
            #expect(json["authenticatorAttachment"] as? String == "cross-platform")

            // Verify response fields
            let inner = try #require(json["response"] as? [String: Any])
            #expect(inner["attestationObject"] as? String == "YXR0ZXN0YXRpb24")
            #expect(inner["clientDataJSON"] as? String == "Y2xpZW50ZGF0YQ")
            #expect(inner["transports"] as? [String] == ["usb"])
            #expect(inner["publicKeyAlgorithm"] as? Int == -7)
        }

        @Test("Authentication.Response JSON encoding")
        func testAuthenticationResponseJSON() throws {
            let authData = makeMinimalAuthData()

            let response = WebAuthn.Authentication.Response(
                credentialId: Data("credential_id".utf8),
                rawAuthenticatorData: authData.rawData,
                signature: Data("sig".utf8),
                user: WebAuthn.User(id: Data("user".utf8)),
                clientExtensionResults: .init(),
                signCount: authData.signCount,
                authenticatorData: authData,
                clientDataJSON: Data("clientdata".utf8)
            )

            let encoded = try response.toJSON()
            let json = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

            // Verify envelope fields
            #expect(json["id"] as? String == "Y3JlZGVudGlhbF9pZA")
            #expect(json["rawId"] as? String == "Y3JlZGVudGlhbF9pZA")
            #expect(json["type"] as? String == "public-key")
            #expect(json["authenticatorAttachment"] as? String == "cross-platform")

            // Verify response fields
            let inner = try #require(json["response"] as? [String: Any])
            #expect(inner["clientDataJSON"] as? String == "Y2xpZW50ZGF0YQ")
            #expect(inner["signature"] as? String == "c2ln")
            #expect(inner["userHandle"] as? String == "dXNlcg")
        }

        @Test("Authentication.Response JSON encoding - no userHandle")
        func testAuthenticationResponseJSONNoUserHandle() throws {
            let authData = makeMinimalAuthData()

            let response = WebAuthn.Authentication.Response(
                credentialId: Data("credential_id".utf8),
                rawAuthenticatorData: authData.rawData,
                signature: Data("sig".utf8),
                user: nil,
                clientExtensionResults: .init(),
                signCount: authData.signCount,
                authenticatorData: authData,
                clientDataJSON: Data("clientdata".utf8)
            )

            let encoded = try response.toJSON()
            let json = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

            let inner = try #require(json["response"] as? [String: Any])
            #expect(inner["userHandle"] == nil)
        }
    }

    // MARK: - ClientData JSON

    @Suite("ClientData JSON")
    struct ClientDataJSONTests {

        @Test("clientDataJSON has correct fields")
        func testClientDataJSONFields() throws {
            let origin = try WebAuthn.Origin("https://example.com")
            let challenge = Data([0x01, 0x02, 0x03])

            let clientData = WebAuthn.ClientData.webauthn(
                type: "webauthn.create",
                challenge: challenge,
                origin: origin,
                rpId: "example.com",
                crossOrigin: false
            )

            let json =
                try JSONSerialization.jsonObject(with: clientData.clientDataJSON!) as! [String: Any]

            #expect(json["type"] as? String == "webauthn.create")
            #expect(json["challenge"] as? String == "AQID")  // base64url of [0x01, 0x02, 0x03]
            #expect(json["origin"] as? String == "https://example.com")
            #expect(json["crossOrigin"] as? Bool == false)
        }
    }
}
