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

/// Test parsing and decoding of WebAuthn data structures.
///
/// Tests the binary parsing of WebAuthn.AuthenticatorData, AttestationStatement decoding,
/// and WebAuthn.ExtensionOutputs parsing from CBOR.
@Suite("WebAuthn Structures Tests")
struct WebAuthnStructuresTests {

    // MARK: - WebAuthn.AuthenticatorData Tests

    @Test("WebAuthn.AuthenticatorData binary parsing - real example")
    func testAuthenticatorDataParsing() throws {
        // Real WebAuthn.AuthenticatorData from a YubiKey makeCredential response
        // This is the same base64 example used in Java's SerializationTest.java:283-287
        let base64 = """
            5Yaf4EYzO6ALp/K7s+p+BQLPSCYVYcKLZptoXwxqQztFAAAAAhSaICGO9kEzlriB+NW38fUAMA5hR\
            7Wj16h/z28qvtukB63QcIhzJ/sUkkJPfsU+KzdCFeaF2mZ80gSROEtELSHniKUBAgMmIAEhWCAOYUe1\
            o9eof89vKr7bLZhH7nLY4wjKx5oxa66Kv0JjXiJYIKyPUlRxXHJjLrACafd/1stM7DyX120jDO7BlwqYsJyJ
            """

        let data = try #require(Data(base64Encoded: base64), "Failed to decode base64")
        let authData = try #require(
            WebAuthn.AuthenticatorData(data: data),
            "Failed to parse WebAuthn.AuthenticatorData"
        )

        // Verify basic structure
        #expect(authData.rpIdHash.count == 32)
        #expect(authData.signCount == 2)
        #expect(authData.flags.contains(.userPresent))
        #expect(authData.flags.contains(.attestedCredentialData))

        // Verify attested credential data is present
        let attestedData = try #require(authData.attestedCredentialData, "Missing attested credential data")

        #expect(attestedData.aaguid.count == 16)
        #expect(attestedData.credentialId.count > 0)

        // Verify we got an EC2 COSE key (ES256 uses P-256)
        guard case .ec2(.es256, _, 1, let x, let y) = attestedData.credentialPublicKey else {
            Issue.record("Expected EC2 ES256 P-256 key")
            return
        }
        #expect(x.count == 32)
        #expect(y.count == 32)
    }

    @Test("WebAuthn.AuthenticatorData binary parsing - minimal")
    func testAuthenticatorDataMinimal() throws {
        // Minimal authenticatorData: rpIdHash (32) + flags (1) + signCount (4) = 37 bytes
        var data = Data()
        data.append(randomBytes(count: 32))  // rpIdHash
        data.append(0x01)  // flags: UP only
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x05])  // signCount = 5 (big-endian)

        let authData = try #require(
            WebAuthn.AuthenticatorData(data: data),
            "Failed to parse minimal WebAuthn.AuthenticatorData"
        )

        #expect(authData.rpIdHash.count == 32)
        #expect(authData.flags.contains(.userPresent))
        #expect(authData.signCount == 5)
        #expect(authData.attestedCredentialData == nil)
        #expect(authData.extensions == nil)
    }

    @Test("WebAuthn.AuthenticatorData parsing - invalid size")
    func testAuthenticatorDataInvalidSize() {
        let tooSmall = Data(count: 36)  // Need at least 37 bytes
        #expect(WebAuthn.AuthenticatorData(data: tooSmall) == nil)
    }

    @Test("WebAuthn.AuthenticatorData parsing - invalid attested credential data")
    func testAuthenticatorDataInvalidAttestedData() {
        var data = Data()
        data.append(randomBytes(count: 32))  // rpIdHash
        data.append(0x41)  // flags: UP + AT (claims attested data present)
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount
        // But don't include the attested credential data!

        #expect(WebAuthn.AuthenticatorData(data: data) == nil)
    }

    // MARK: - AttestationStatement Tests

    @Test("WebAuthn.AttestationStatement.Packed CBOR decoding")
    func testPackedAttestationCBOR() throws {
        let sig = randomBytes(count: 70)
        let cert1 = randomBytes(count: 100)
        let cert2 = randomBytes(count: 100)

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .textString("sig"): .byteString(sig),
            .textString("alg"): .negativeInt(6),  // ES256 (-7)
            .textString("x5c"): .array([.byteString(cert1), .byteString(cert2)]),
        ]

        let packed = try #require(
            WebAuthn.AttestationStatement.Packed(cbor: .map(cborMap)),
            "Failed to decode WebAuthn.AttestationStatement.Packed"
        )

        #expect(packed.sig == sig)
        #expect(packed.alg == -7)
        #expect(packed.x5c?.count == 2)
        #expect(packed.x5c?[0] == cert1)
        #expect(packed.x5c?[1] == cert2)
        #expect(packed.ecdaaKeyId == nil)
    }

    @Test("WebAuthn.AttestationStatement.Packed CBOR decoding - self-attestation")
    func testPackedSelfAttestation() throws {
        let sig = randomBytes(count: 70)

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .textString("sig"): .byteString(sig),
            .textString("alg"): .negativeInt(6),  // ES256 (-7)
        ]

        let packed = try #require(
            WebAuthn.AttestationStatement.Packed(cbor: .map(cborMap)),
            "Failed to decode WebAuthn.AttestationStatement.Packed"
        )

        #expect(packed.sig == sig)
        #expect(packed.alg == -7)
        #expect(packed.x5c == nil)
        #expect(packed.ecdaaKeyId == nil)
    }

    @Test("WebAuthn.AttestationStatement.FIDOU2F CBOR decoding")
    func testFIDOU2FAttestationCBOR() throws {
        let sig = randomBytes(count: 70)
        let cert = randomBytes(count: 100)

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .textString("sig"): .byteString(sig),
            .textString("x5c"): .array([.byteString(cert)]),
        ]

        let fidoU2F = try #require(
            WebAuthn.AttestationStatement.FIDOU2F(cbor: .map(cborMap)),
            "Failed to decode WebAuthn.AttestationStatement.FIDOU2F"
        )

        #expect(fidoU2F.sig == sig)
        #expect(fidoU2F.x5c.count == 1)
        #expect(fidoU2F.x5c[0] == cert)
    }

    @Test("WebAuthn.AttestationStatement.Apple CBOR decoding")
    func testAppleAttestationCBOR() throws {
        let cert1 = randomBytes(count: 100)
        let cert2 = randomBytes(count: 100)

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .textString("x5c"): .array([.byteString(cert1), .byteString(cert2)])
        ]

        let apple = try #require(
            WebAuthn.AttestationStatement.Apple(cbor: .map(cborMap)),
            "Failed to decode WebAuthn.AttestationStatement.Apple"
        )

        #expect(apple.x5c.count == 2)
        #expect(apple.x5c[0] == cert1)
        #expect(apple.x5c[1] == cert2)
    }

    @Test("AttestationStatement - unknown format fallback")
    func testAttestationStatementUnknownFormat() throws {
        // Create a CTAP.MakeCredential.Response with an unknown attestation format
        // Build valid authData: rpIdHash (32) + flags (1) + signCount (4)
        var authData = Data()
        authData.append(randomBytes(count: 32))  // rpIdHash
        authData.append(0x01)  // flags: user present
        authData.append(contentsOf: [0, 0, 0, 0])  // signCount = 0

        let statement: [CBOR.Value: CBOR.Value] = [
            .textString("someProp"): .textString("someValue")
        ]

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("unknown-format"),  // fmt
            .unsignedInt(0x02): .byteString(authData),  // authData
            .unsignedInt(0x03): .map(statement),  // attStmt
        ]

        let credData = try #require(
            CTAP.MakeCredential.Response(cbor: .map(cborMap)),
            "Failed to decode CTAP.MakeCredential.Response"
        )

        // Verify unknown format is preserved
        if case let .unknown(format) = credData.attestationStatement {
            #expect(format == "unknown-format")
        } else {
            Issue.record("Expected .unknown case for unknown format")
        }
    }

    // MARK: - WebAuthn.ExtensionOutputs Tests

    @Test("WebAuthn.ExtensionOutputs CBOR decoding")
    func testExtensionOutputsCBOR() throws {
        let largeBlobKey = randomBytes(count: 32)

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .textString("credProps"): .map([.textString("rk"): .boolean(true)]),
            .textString("largeBlobKey"): .byteString(largeBlobKey),
            .textString("hmac-secret"): .boolean(true),
            .textString("credProtect"): .unsignedInt(3),
            .textString("minPINLength"): .unsignedInt(6),
            .textString("customExtension"): .textString("custom-value"),
        ]

        let extensions = try #require(
            WebAuthn.ExtensionOutputs(cbor: .map(cborMap)),
            "Failed to decode WebAuthn.ExtensionOutputs"
        )

        #expect(extensions.credProps?.rk == true)
        #expect(extensions.largeBlobKey == largeBlobKey)
        #expect(extensions.hmacSecret == true)
        #expect(extensions.credProtect == .userVerificationRequired)
        #expect(extensions.minPINLength == 6)
    }

    @Test("WebAuthn.ExtensionOutputs CBOR decoding - empty")
    func testExtensionOutputsEmpty() throws {
        let cborMap: [CBOR.Value: CBOR.Value] = [:]

        let extensions = try #require(
            WebAuthn.ExtensionOutputs(cbor: .map(cborMap)),
            "Failed to decode empty WebAuthn.ExtensionOutputs"
        )

        #expect(extensions.credProps == nil)
        #expect(extensions.largeBlobKey == nil)
        #expect(extensions.hmacSecret == nil)
        #expect(extensions.credProtect == nil)
        #expect(extensions.minPINLength == nil)
        #expect(extensions.thirdPartyPayment == nil)
    }

    // MARK: - Test Helpers

    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
