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

/// Test parsing of CTAP2 response structures: AuthenticatorData and AttestationStatement.
/// Uses test data from yubikit-android's SerializationTest.
@Suite("Response Parsing Tests")
struct ResponseParsingTests {

    // MARK: - WebAuthn.AuthenticatorData Tests

    @Test("WebAuthn.AuthenticatorData binary parsing - real example")
    func testAuthenticatorDataParsing() throws {
        // Real AuthenticatorData from a YubiKey makeCredential response
        // Structure: rpIdHash (32) + flags (1) + signCount (4) + attestedCredentialData
        let data = Data([
            // rpIdHash (32 bytes)
            0xe5, 0x86, 0x9f, 0xe0, 0x46, 0x33, 0x3b, 0xa0, 0x0b, 0xa7, 0xf2, 0xbb,
            0xb3, 0xea, 0x7e, 0x05, 0x02, 0xcf, 0x48, 0x26, 0x15, 0x61, 0xc2, 0x8b,
            0x66, 0x9b, 0x68, 0x5f, 0x0c, 0x6a, 0x43, 0x3b,
            // flags: 0x45 = UP | UV | AT
            0x45,
            // signCount: 2 (big-endian)
            0x00, 0x00, 0x00, 0x02,
            // aaguid (16 bytes)
            0x14, 0x9a, 0x20, 0x21, 0x8e, 0xf6, 0x41, 0x33, 0x96, 0xb8, 0x81, 0xf8,
            0xd5, 0xb7, 0xf1, 0xf5,
            // credentialIdLength: 48 (big-endian)
            0x00, 0x30,
            // credentialId (48 bytes)
            0x0e, 0x61, 0x47, 0xb5, 0xa3, 0xd7, 0xa8, 0x7f, 0xcf, 0x6f, 0x2a, 0xbe,
            0xdb, 0xa4, 0x07, 0xad, 0xd0, 0x70, 0x88, 0x73, 0x27, 0xfb, 0x14, 0x92,
            0x42, 0x4f, 0x7e, 0xc5, 0x3e, 0x2b, 0x37, 0x42, 0x15, 0xe6, 0x85, 0xda,
            0x66, 0x7c, 0xd2, 0x04, 0x91, 0x38, 0x4b, 0x44, 0x2d, 0x21, 0xe7, 0x88,
            // credentialPublicKey (COSE_Key EC2 P-256)
            0xa5,  // map(5)
            0x01, 0x02,  // kty: EC2
            0x03, 0x26,  // alg: ES256 (-7)
            0x20, 0x01,  // crv: P-256 (1)
            0x21, 0x58, 0x20,  // x: 32 bytes
            0x0e, 0x61, 0x47, 0xb5, 0xa3, 0xd7, 0xa8, 0x7f, 0xcf, 0x6f, 0x2a, 0xbe,
            0xdb, 0x2d, 0x98, 0x47, 0xee, 0x72, 0xd8, 0xe3, 0x08, 0xca, 0xc7, 0x9a,
            0x31, 0x6b, 0xae, 0x8a, 0xbf, 0x42, 0x63, 0x5e,
            0x22, 0x58, 0x20,  // y: 32 bytes
            0xac, 0x8f, 0x52, 0x54, 0x71, 0x5c, 0x72, 0x63, 0x2e, 0xb0, 0x02, 0x69,
            0xf7, 0x7f, 0xd6, 0xcb, 0x4c, 0xec, 0x3c, 0x97, 0xd7, 0x6d, 0x23, 0x0c,
            0xee, 0xc1, 0x97, 0x0a, 0x98, 0xb0, 0x9c, 0x89,
        ])
        let authData = try #require(
            WebAuthn.AuthenticatorData(data: data),
            "Failed to parse WebAuthn.AuthenticatorData"
        )

        #expect(authData.rpIdHash.count == 32)
        #expect(authData.signCount == 2)
        #expect(authData.flags.contains(.userPresent))
        #expect(authData.flags.contains(.attestedCredentialData))

        let attestedData = try #require(authData.attestedCredentialData, "Missing attested credential data")

        #expect(attestedData.aaguid.rawValue.count == 16)
        #expect(attestedData.credentialId.count > 0)

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
            .textString("alg"): .int(-7),  // ES256
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
            .textString("alg"): .int(-7),  // ES256
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
        var authData = Data()
        authData.append(randomBytes(count: 32))  // rpIdHash
        authData.append(0x01)  // flags: user present
        authData.append(contentsOf: [0, 0, 0, 0])  // signCount = 0

        let statement: [CBOR.Value: CBOR.Value] = [
            .textString("someProp"): .textString("someValue")
        ]

        let cborMap: [CBOR.Value: CBOR.Value] = [
            .int(0x01): .textString("unknown-format"),  // fmt
            .int(0x02): .byteString(authData),  // authData
            .int(0x03): .map(statement),  // attStmt
        ]

        let credData = try #require(
            CTAP2.MakeCredential.Response(cbor: .map(cborMap)),
            "Failed to decode CTAP.MakeCredential.Response"
        )

        if case let .unknown(format) = credData.attestationObject.statement {
            #expect(format == "unknown-format")
        } else {
            Issue.record("Expected .unknown case for unknown format")
        }
    }

    // MARK: - Test Helpers

    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
