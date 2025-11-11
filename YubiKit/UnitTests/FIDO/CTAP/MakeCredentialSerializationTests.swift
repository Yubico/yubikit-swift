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
/// Verifies that PublicKeyCredential types and CredentialData can be encoded to CBOR
/// and decoded back without data loss (round-trip testing).
@Suite("MakeCredential CBOR Serialization Tests")
struct MakeCredentialSerializationTests {

    // MARK: - PublicKeyCredential Types Tests

    @Test("PublicKeyCredentialRPEntity CBOR round-trip")
    func testRPEntityCBOR() throws {
        let rp = PublicKeyCredentialRPEntity(id: "example.com", name: "An Example Company")

        let encoded = rp.cbor()
        let decoded = try #require(
            PublicKeyCredentialRPEntity(cbor: encoded),
            "Failed to decode PublicKeyCredentialRPEntity"
        )

        #expect(decoded.id == rp.id)
        #expect(decoded.name == rp.name)
    }

    @Test("PublicKeyCredentialRPEntity CBOR round-trip - no name")
    func testRPEntityCBORNoName() throws {
        let rp = PublicKeyCredentialRPEntity(id: "example.com", name: nil)

        let encoded = rp.cbor()
        let decoded = try #require(
            PublicKeyCredentialRPEntity(cbor: encoded),
            "Failed to decode PublicKeyCredentialRPEntity"
        )

        #expect(decoded.id == rp.id)
        #expect(decoded.name == nil)
    }

    @Test("PublicKeyCredentialUserEntity CBOR round-trip")
    func testUserEntityCBOR() throws {
        let userId = randomBytes(count: 16)
        let user = PublicKeyCredentialUserEntity(
            id: userId,
            name: "user@example.com",
            displayName: "A. User"
        )

        let encoded = user.cbor()
        let decoded = try #require(
            PublicKeyCredentialUserEntity(cbor: encoded),
            "Failed to decode PublicKeyCredentialUserEntity"
        )

        #expect(decoded.id == user.id)
        #expect(decoded.name == user.name)
        #expect(decoded.displayName == user.displayName)
    }

    @Test("PublicKeyCredentialUserEntity CBOR round-trip - minimal")
    func testUserEntityCBORMinimal() throws {
        let userId = randomBytes(count: 32)
        let user = PublicKeyCredentialUserEntity(id: userId, name: nil, displayName: nil)

        let encoded = user.cbor()
        let decoded = try #require(
            PublicKeyCredentialUserEntity(cbor: encoded),
            "Failed to decode PublicKeyCredentialUserEntity"
        )

        #expect(decoded.id == user.id)
        #expect(decoded.name == nil)
        #expect(decoded.displayName == nil)
    }

    @Test("PublicKeyCredentialParameters CBOR round-trip")
    func testParametersCBOR() throws {
        let param = PublicKeyCredentialParameters(type: "public-key", alg: -7)

        let encoded = param.cbor()
        let decoded = try #require(
            PublicKeyCredentialParameters(cbor: encoded),
            "Failed to decode PublicKeyCredentialParameters"
        )

        #expect(decoded.type == param.type)
        #expect(decoded.alg == param.alg)
    }

    @Test("PublicKeyCredentialDescriptor CBOR round-trip")
    func testDescriptorCBOR() throws {
        let credentialId = randomBytes(count: 32)
        let descriptor = PublicKeyCredentialDescriptor(
            type: "public-key",
            id: credentialId,
            transports: ["usb", "nfc"]
        )

        let encoded = descriptor.cbor()
        let decoded = try #require(
            PublicKeyCredentialDescriptor(cbor: encoded),
            "Failed to decode PublicKeyCredentialDescriptor"
        )

        #expect(decoded.type == descriptor.type)
        #expect(decoded.id == descriptor.id)
        #expect(decoded.transports == descriptor.transports)
    }

    @Test("PublicKeyCredentialDescriptor CBOR round-trip - no transports")
    func testDescriptorCBORNoTransports() throws {
        let credentialId = randomBytes(count: 32)
        let descriptor = PublicKeyCredentialDescriptor(
            type: "public-key",
            id: credentialId,
            transports: nil
        )

        let encoded = descriptor.cbor()
        let decoded = try #require(
            PublicKeyCredentialDescriptor(cbor: encoded),
            "Failed to decode PublicKeyCredentialDescriptor"
        )

        #expect(decoded.type == descriptor.type)
        #expect(decoded.id == descriptor.id)
        #expect(decoded.transports == nil)
    }

    // MARK: - CredentialData Tests

    @Test("CredentialData CBOR decoding - packed attestation")
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
        let credentialData = try #require(CredentialData(cbor: decoded), "Failed to decode CredentialData")

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

    @Test("CredentialData CBOR decoding - none attestation")
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
        let credentialData = try #require(CredentialData(cbor: decoded), "Failed to decode CredentialData")

        #expect(credentialData.format == "none")
        guard case .none = credentialData.attestationStatement else {
            Issue.record("Expected none attestation statement")
            return
        }
    }

    @Test("CredentialData CBOR decoding - with largeBlobKey")
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
        let credentialData = try #require(CredentialData(cbor: decoded), "Failed to decode CredentialData")

        #expect(credentialData.largeBlobKey == largeBlobKey)
    }

    @Test("CredentialData CBOR decoding - missing required field")
    func testCredentialDataMissingField() throws {
        // Missing authData field
        let response: [CBOR.Value: CBOR.Value] = [
            .unsignedInt(0x01): .textString("none"),
            .unsignedInt(0x03): .map([:]),
        ]

        let cborData = CBOR.Value.map(response).encode()
        let decoded: CBOR.Value = try #require(try cborData.decode(), "Failed to decode CBOR")

        #expect(CredentialData(cbor: decoded) == nil)
    }

    // MARK: - Test Helpers

    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}

// MARK: - CBOR Decodable Extensions (Test Support)

extension PublicKeyCredentialRPEntity: CBOR.Decodable {
    public init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let id = map["id"]?.stringValue else {
            return nil
        }

        let name = map["name"]?.stringValue
        self.init(id: id, name: name)
    }
}

extension PublicKeyCredentialUserEntity: CBOR.Decodable {
    public init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let id = map["id"]?.dataValue else {
            return nil
        }

        let name = map["name"]?.stringValue
        let displayName = map["displayName"]?.stringValue
        self.init(id: id, name: name, displayName: displayName)
    }
}

extension PublicKeyCredentialParameters: CBOR.Decodable {
    public init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let type = map["type"]?.stringValue,
            let alg = map["alg"]?.intValue
        else {
            return nil
        }

        self.init(type: type, alg: alg)
    }
}

extension PublicKeyCredentialDescriptor: CBOR.Decodable {
    public init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        guard let type = map["type"]?.stringValue,
            let id = map["id"]?.dataValue
        else {
            return nil
        }

        let transports: [String]?
        if let transportsArray = map["transports"]?.arrayValue {
            transports = transportsArray.compactMap { $0.stringValue }
        } else {
            transports = nil
        }

        self.init(type: type, id: id, transports: transports)
    }
}
