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

/// Test CBOR encoding and decoding of CTAP2 GetAssertion request/response types.
///
/// Verifies that GetAssertionParameters can be encoded to CBOR correctly
/// and AssertionResponse can be decoded from CBOR without data loss.
@Suite("GetAssertion CBOR Serialization Tests")
struct GetAssertionSerializationTests {

    // MARK: - GetAssertionParameters Encoding Tests

    @Test("GetAssertionParameters CBOR encoding - minimal")
    func testGetAssertionParametersMinimal() throws {
        let clientDataHash = randomBytes(count: 32)
        let params = GetAssertionParameters(
            rpId: "example.com",
            clientDataHash: clientDataHash
        )

        let encoded = params.cbor()
        guard let map = encoded.mapValue else {
            Issue.record("Expected CBOR map")
            return
        }

        // Required parameters
        #expect(map[.unsignedInt(1)]?.stringValue == "example.com")
        #expect(map[.unsignedInt(2)]?.dataValue == clientDataHash)

        // Optional parameters should not be present
        #expect(map[.unsignedInt(3)] == nil)  // allowList
        #expect(map[.unsignedInt(4)] == nil)  // extensions
        #expect(map[.unsignedInt(5)] == nil)  // options
        #expect(map[.unsignedInt(6)] == nil)  // pinUvAuthParam
        #expect(map[.unsignedInt(7)] == nil)  // pinUvAuthProtocol
    }

    @Test("GetAssertionParameters CBOR encoding - with allowList")
    func testGetAssertionParametersWithAllowList() throws {
        let clientDataHash = randomBytes(count: 32)
        let credId1 = randomBytes(count: 32)
        let credId2 = randomBytes(count: 64)

        let params = GetAssertionParameters(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            allowList: [
                PublicKeyCredentialDescriptor(id: credId1, transports: ["usb"]),
                PublicKeyCredentialDescriptor(id: credId2, transports: ["nfc", "usb"]),
            ]
        )

        let encoded = params.cbor()
        guard let map = encoded.mapValue else {
            Issue.record("Expected CBOR map")
            return
        }

        // Verify allowList is present
        guard let allowListValue = map[.unsignedInt(3)]?.arrayValue else {
            Issue.record("Expected allowList array")
            return
        }

        #expect(allowListValue.count == 2)
    }

    @Test("GetAssertionParameters CBOR encoding - with options")
    func testGetAssertionParametersWithOptions() throws {
        let clientDataHash = randomBytes(count: 32)

        let params = GetAssertionParameters(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            options: .init(up: false, uv: true)
        )

        let encoded = params.cbor()
        guard let map = encoded.mapValue else {
            Issue.record("Expected CBOR map")
            return
        }

        // Verify options are present
        guard let optionsMap = map[.unsignedInt(5)]?.mapValue else {
            Issue.record("Expected options map")
            return
        }

        #expect(optionsMap["up"]?.boolValue == false)
        #expect(optionsMap["uv"]?.boolValue == true)
    }

    @Test("GetAssertionParameters CBOR encoding - with PIN/UV auth")
    func testGetAssertionParametersWithPinUvAuth() throws {
        let clientDataHash = randomBytes(count: 32)
        let pinUvAuthParam = randomBytes(count: 16)

        let params = GetAssertionParameters(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            pinUvAuthParam: pinUvAuthParam,
            pinUvAuthProtocol: 2
        )

        let encoded = params.cbor()
        guard let map = encoded.mapValue else {
            Issue.record("Expected CBOR map")
            return
        }

        #expect(map[.unsignedInt(6)]?.dataValue == pinUvAuthParam)
        #expect(map[.unsignedInt(7)]?.intValue == 2)
    }

    @Test("GetAssertionParameters CBOR encoding - empty allowList not encoded")
    func testGetAssertionParametersEmptyAllowList() throws {
        let clientDataHash = randomBytes(count: 32)

        let params = GetAssertionParameters(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            allowList: []  // Empty allowList should not be encoded
        )

        let encoded = params.cbor()
        guard let map = encoded.mapValue else {
            Issue.record("Expected CBOR map")
            return
        }

        // Empty allowList should not be included in CBOR
        #expect(map[.unsignedInt(3)] == nil)
    }

    // MARK: - AssertionResponse Decoding Tests

    @Test("AssertionResponse CBOR decoding - minimal")
    func testAssertionResponseMinimal() throws {
        let rpIdHash = randomBytes(count: 32)
        let signature = randomBytes(count: 70)

        // Build minimal authenticatorData
        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)  // flags: UP only
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount = 1

        // Build CBOR response
        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x02): .byteString(authDataBytes),  // authData
            .unsignedInt(0x03): .byteString(signature),  // signature
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let assertion = try #require(AssertionResponse(cbor: decoded), "Failed to decode AssertionResponse")

        #expect(assertion.authenticatorData.rpIdHash == rpIdHash)
        #expect(assertion.authenticatorData.signCount == 1)
        #expect(assertion.signature == signature)
        #expect(assertion.credential == nil)
        #expect(assertion.user == nil)
        #expect(assertion.numberOfCredentials == nil)
    }

    @Test("AssertionResponse CBOR decoding - with credential")
    func testAssertionResponseWithCredential() throws {
        let rpIdHash = randomBytes(count: 32)
        let signature = randomBytes(count: 70)
        let credentialId = randomBytes(count: 32)

        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x05)  // flags: UP + UV
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x02])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .map([  // credential
                .textString("type"): .textString("public-key"),
                .textString("id"): .byteString(credentialId),
            ]),
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .byteString(signature),
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let assertion = try #require(AssertionResponse(cbor: decoded), "Failed to decode AssertionResponse")

        #expect(assertion.credential?.type == "public-key")
        #expect(assertion.credential?.id == credentialId)
    }

    @Test("AssertionResponse CBOR decoding - with user (resident key)")
    func testAssertionResponseWithUser() throws {
        let rpIdHash = randomBytes(count: 32)
        let signature = randomBytes(count: 70)
        let userId = randomBytes(count: 16)

        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x05)
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x03])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .byteString(signature),
            .unsignedInt(0x04): .map([  // user
                .textString("id"): .byteString(userId),
                .textString("name"): .textString("alice@example.com"),
                .textString("displayName"): .textString("Alice"),
            ]),
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let assertion = try #require(AssertionResponse(cbor: decoded), "Failed to decode AssertionResponse")

        #expect(assertion.user?.id == userId)
        #expect(assertion.user?.name == "alice@example.com")
        #expect(assertion.user?.displayName == "Alice")
    }

    @Test("AssertionResponse CBOR decoding - with numberOfCredentials")
    func testAssertionResponseWithNumberOfCredentials() throws {
        let rpIdHash = randomBytes(count: 32)
        let signature = randomBytes(count: 70)

        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x04])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .byteString(signature),
            .unsignedInt(0x05): .unsignedInt(3),  // numberOfCredentials
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let assertion = try #require(AssertionResponse(cbor: decoded), "Failed to decode AssertionResponse")

        #expect(assertion.numberOfCredentials == 3)
    }

    @Test("AssertionResponse CBOR decoding - with largeBlobKey")
    func testAssertionResponseWithLargeBlobKey() throws {
        let rpIdHash = randomBytes(count: 32)
        let signature = randomBytes(count: 70)
        let largeBlobKey = randomBytes(count: 32)

        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x05])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x02): .byteString(authDataBytes),
            .unsignedInt(0x03): .byteString(signature),
            .unsignedInt(0x07): .byteString(largeBlobKey),  // largeBlobKey (0x07 in CTAP 2.2)
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")
        let assertion = try #require(AssertionResponse(cbor: decoded), "Failed to decode AssertionResponse")

        #expect(assertion.largeBlobKey == largeBlobKey)
    }

    @Test("AssertionResponse CBOR decoding - missing required field")
    func testAssertionResponseMissingField() throws {
        // Missing signature field
        let rpIdHash = randomBytes(count: 32)
        var authDataBytes = Data()
        authDataBytes.append(rpIdHash)
        authDataBytes.append(0x01)
        authDataBytes.append(contentsOf: [0x00, 0x00, 0x00, 0x01])

        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x02): .byteString(authDataBytes)
            // Missing signature (0x03)
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")

        #expect(AssertionResponse(cbor: decoded) == nil)
    }

    // MARK: - Test Helpers

    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
