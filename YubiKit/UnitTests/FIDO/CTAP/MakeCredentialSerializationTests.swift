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

/// Test CBOR encoding and decoding of CTAP2 MakeCredential request/response types.
///
/// Verifies that PublicKeyCredential types and CTAP.MakeCredential.Response can be encoded to CBOR
/// and decoded back without data loss (round-trip testing).
@Suite("MakeCredential CBOR Serialization Tests")
struct MakeCredentialSerializationTests {

    // MARK: - CTAP.MakeCredential.Response Tests

    @Test("CTAP.MakeCredential.Response CBOR decoding - packed attestation")
    func testCredentialDataCBOR() throws {
        let rpIdHash = randomBytes(count: 32)
        let credentialId = randomBytes(count: 32)

        // Build authenticatorData
        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)  // rpIdHash (32)
        authDataBytes.append(0x41)  // flags: UP + AT
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount = 1

        // Add attested credential data
        authDataBytes.append(randomBytes(count: 16))  // aaguid
        authDataBytes.append(contentsOf: [0x00, 0x20])  // credentialId length = 32
        authDataBytes.append(credentialId)

        // Add credential public key (minimal COSE key for ES256)
        // Note: negativeInt(6) encodes as -7 in CBOR (n = -1 - 6 = -7)
        let coseKey: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(1): .unsignedInt(2),  // kty: EC2
            .unsignedInt(3): .negativeInt(6),  // alg: ES256 (-7)
            .negativeInt(0): .unsignedInt(1),  // crv: P-256
            .negativeInt(1): .byteString(randomBytes(count: 32)),  // x
            .negativeInt(2): .byteString(randomBytes(count: 32)),  // y
        ]
        authDataBytes.append(CBOR.Value.map(coseKey).encode())

        // Build CBOR response
        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("packed"),  // fmt
            .unsignedInt(0x02): .byteString(authDataBytes),  // authData
            .unsignedInt(0x03): .map([  // attStmt
                .textString("sig"): .byteString(randomBytes(count: 70)),
                .textString("alg"): .negativeInt(6),  // ES256 (-7)
            ]),
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let credentialData = try #require(
            CTAP.MakeCredential.Response(cbor: decoded),
            "Failed to decode CTAP.MakeCredential.Response"
        )

        #expect(credentialData.format == "packed")
        #expect(credentialData.authenticatorData.rpIdHash.count == 32)
        #expect(credentialData.authenticatorData.signCount == 1)

        // Verify strongly-typed attestation statement
        guard case let .packed(packed) = credentialData.attestationStatement else {
            Issue.record("Expected packed attestation statement")
            return
        }

        #expect(packed.sig.count == 70)
        #expect(packed.alg == -7)
        #expect(packed.x5c == nil)
    }

    @Test("CTAP.MakeCredential.Response CBOR decoding - none attestation")
    func testCredentialDataNoneAttestation() throws {
        let rpIdHash = randomBytes(count: 32)

        // Build minimal authenticatorData (no AT flag)
        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)  // flags: UP only
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x01])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("none"),
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .map([:]),  // empty attStmt for "none"
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let credentialData = try #require(
            CTAP.MakeCredential.Response(cbor: decoded),
            "Failed to decode CTAP.MakeCredential.Response"
        )

        #expect(credentialData.format == "none")
        guard case .none = credentialData.attestationStatement else {
            Issue.record("Expected none attestation statement")
            return
        }
    }

    @Test("CTAP.MakeCredential.Response CBOR decoding - with largeBlobKey")
    func testCredentialDataWithLargeBlobKey() throws {
        let rpIdHash = randomBytes(count: 32)
        let largeBlobKey = randomBytes(count: 32)

        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x01])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("none"),
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .map([:]),
            .unsignedInt(0x05): .byteString(largeBlobKey),  // largeBlobKey
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let credentialData = try #require(
            CTAP.MakeCredential.Response(cbor: decoded),
            "Failed to decode CTAP.MakeCredential.Response"
        )

        #expect(credentialData.largeBlobKey == largeBlobKey)
    }

    @Test("CTAP.MakeCredential.Response CBOR decoding - missing required field")
    func testCredentialDataMissingField() throws {
        // Missing authData field
        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("none"),
            .unsignedInt(0x03): .map([:]),
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")

        #expect(CTAP.MakeCredential.Response(cbor: decoded) == nil)
    }

    // MARK: - Test Helpers

    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}

// MARK: - Test Support

// CBOR.Decodable conformances for PublicKeyCredential types are now in the main library
