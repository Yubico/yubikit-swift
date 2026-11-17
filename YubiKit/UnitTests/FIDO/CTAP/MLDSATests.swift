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

@_spi(YubiInternal) @testable import YubiKit

@Suite("ML-DSA FIDO2")
struct MLDSATests {
    private static let algorithms: [COSE.Algorithm] = [.mlDSA44, .mlDSA65, .mlDSA87]
    private static let keySizes = [1312, 1952, 2592]
    private static let signatureSizes = [2420, 3309, 4627]

    @Test("AKP keys convert to ML-DSA and SPKI", arguments: 0..<3)
    func publicKey(index: Int) throws {
        let alg = Self.algorithms[index]
        let pub = Data(repeating: 0xAB, count: Self.keySizes[index])
        let kid = Data([1, 2, 3])
        let wire = Self.akp(algorithm: -48 - index, pub: pub, kid: kid)
        let key = try #require(COSE.Key(cbor: wire))
        #expect(key == .akp(alg: alg, kid: kid, pub: pub))
        #expect(key.algorithm == alg)
        #expect(key.cbor() == wire)

        let converted = try #require(PublicKey(cose: key))
        guard case .mlDSA(let mlDSA) = converted else {
            Issue.record("Expected ML-DSA public key")
            return
        }
        #expect(mlDSA.keyData == pub)
        #expect(mlDSA.parameterSet == MLDSA.ParameterSet.allCases[index])
        // DER SPKI: algorithm OID 2.16.840.1.101.3.4.3.{17,18,19}, absent parameters.
        let lengths: [[UInt8]] = [[0x05, 0x32, 0x05, 0x21], [0x07, 0xB2, 0x07, 0xA1], [0x0A, 0x32, 0x0A, 0x21]]
        let length = lengths[index]
        let prefix = Data([
            0x30, 0x82, length[0], length[1], 0x30, 0x0B, 0x06, 0x09,
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, UInt8(17 + index),
            0x03, 0x82, length[2], length[3], 0x00,
        ])
        #expect(converted.spki == prefix + pub)
    }

    @Test("ML-DSA conversion rejects incorrect key lengths", arguments: 0..<3)
    func incorrectLength(index: Int) throws {
        for size in [0, Self.keySizes[index] - 1, Self.keySizes[index] + 1] {
            let key = try #require(COSE.Key(cbor: Self.akp(algorithm: -48 - index, pub: Data(count: size))))
            #expect(PublicKey(cose: key) == nil)
        }
        #expect(COSE.Key(cbor: .map([.int(1): .int(7), .int(3): .int(-48)])) == nil)
        #expect(COSE.Key(cbor: .map([.int(1): .int(7), .int(3): .int(-48), .int(-1): .int(1)])) == nil)
    }

    @Test("Unknown algorithms and key types retain their algorithm and CBOR")
    func unknownKeys() throws {
        for kty in [7, 99] {
            let wire: CBOR.Value = .map([
                .int(1): .int(kty), .int(3): .int(-999), .int(-1): .byteString(Data([1, 2])),
            ])
            let key = try #require(COSE.Key(cbor: wire))
            #expect(key.algorithm == .other(-999))
            #expect(key.cbor() == wire)
            #expect(PublicKey(cose: key) == nil)
        }
        let key = try #require(COSE.Key(cbor: .map([.int(1): .int(99)])))
        #expect(key.algorithm == nil)
    }

    @Test("GetInfo discovers ML-DSA and unknown algorithms")
    func discovery() throws {
        let wire: CBOR.Value = .map([
            .int(1): .array([.textString("FIDO_2_1")]),
            .int(3): .byteString(Data(count: 16)),
            .int(4): .map([:]),
            .int(10): .array(
                [-48, -49, -50, -999].map { raw in
                    .map([.textString("type"): .textString("public-key"), .textString("alg"): .int(raw)])
                }
            ),
        ])
        let info = try #require(CTAP2.GetInfo.Response(cbor: wire))
        #expect(info.algorithms == Self.algorithms + [.other(-999)])
    }

    @Test("ML-DSA registration and assertions preserve keys and signatures", arguments: 0..<3)
    func ceremony(index: Int) async throws {
        let rawAlgorithm = -48 - index
        let pub = Data(repeating: 0xAB, count: Self.keySizes[index])
        let key = Self.akp(algorithm: rawAlgorithm, pub: pub)
        let optionsJSON = """
            {"challenge":"AQID","rp":{"id":"example.com"},"user":{"id":"AQ","name":"test"},
             "pubKeyCredParams":[{"type":"public-key","alg":\(rawAlgorithm)}],
             "authenticatorSelection":{"userVerification":"discouraged"},"attestation":"direct"}
            """
        let options = try WebAuthn.Registration.Options.from(json: Data(optionsJSON.utf8))
        #expect(options.pubKeyCredParams == [Self.algorithms[index]])

        let authData = Self.authData(key: key)
        let signature = Data(repeating: 0xCD, count: Self.signatureSizes[index])
        let response = try #require(
            CTAP2.MakeCredential.Response(
                cbor: .map([
                    .int(1): .textString("packed"), .int(2): .byteString(authData),
                    .int(3): .map([.textString("alg"): .int(rawAlgorithm), .textString("sig"): .byteString(signature)]),
                ])
            )
        )
        let mock = MockCTAP2Backend()
        mock.onGetInfo = { .stub() }
        mock.onMakeCredential = { parameters in
            #expect(parameters.pubKeyCredParams == [Self.algorithms[index]])
            let sent = parameters.cbor().mapValue?[.int(4)]?.arrayValue
            #expect(
                sent == [
                    .map([.textString("type"): .textString("public-key"), .textString("alg"): .int(rawAlgorithm)])
                ]
            )
            return .mocked(.finished(response))
        }
        let client = try WebAuthn.Client.make(backend: mock)
        let registration = try await client.makeCredential(options, authorization: .uvOnly).value
        let encoded = try JSONEncoder().encode(registration)
        let envelope = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let json = try #require(envelope["response"] as? [String: Any])
        #expect(json["publicKeyAlgorithm"] as? Int == rawAlgorithm)
        let encodedKey = try #require(json["publicKey"] as? String)
        let publicKey = try #require(PublicKey(cose: registration.publicKey))
        #expect(encodedKey == publicKey.spki.base64URLEncodedString())
        #expect(registration.rawAuthenticatorData == authData)
        #expect(json["attestationObject"] as? String == registration.rawAttestationObject.base64URLEncodedString())

        let assertionAuthData = Data(count: 32) + Data([1, 0, 0, 0, 1])
        let assertion = try #require(
            CTAP2.GetAssertion.Response(
                cbor: .map([
                    .int(1): .map([
                        .textString("type"): .textString("public-key"), .textString("id"): .byteString(Data([1])),
                    ]),
                    .int(2): .byteString(assertionAuthData), .int(3): .byteString(signature),
                ])
            )
        )
        mock.onGetAssertion = { _ in .mocked(.finished(assertion)) }
        let matches = try await client.getAssertion(
            .init(
                challenge: Data([1]),
                rpId: "example.com",
                allowCredentials: [.init(id: Data([1]))],
                userVerification: .discouraged
            ),
            authorization: .uvOnly
        ).value
        #expect(matches.first?.signature == signature)
    }

    @Test("Registration JSON retains the algorithm for future key types")
    func unknownRegistration() throws {
        let wire: CBOR.Value = .map([.int(1): .int(99), .int(3): .int(-999)])
        let authData = try #require(WebAuthn.AuthenticatorData(data: Self.authData(key: wire)))
        let response = WebAuthn.Registration.Response(
            credentialId: Data([1]),
            rawAttestationObject: WebAuthn.AttestationObject(authenticatorData: authData).rawData,
            rawAuthenticatorData: authData.rawData,
            attestationStatement: .none,
            transports: [.usb],
            clientExtensionResults: .init(),
            publicKey: try #require(authData.attestedCredentialData).credentialPublicKey,
            aaguid: try #require(WebAuthn.AAGUID(Data(count: 16))),
            signCount: 1,
            authenticatorAttachment: .crossPlatform,
            authenticatorData: authData,
            clientDataJSON: Data([1])
        )
        let envelope = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(response)) as? [String: Any]
        )
        let json = try #require(envelope["response"] as? [String: Any])
        #expect(json["publicKeyAlgorithm"] as? Int == -999)
        #expect(json["publicKey"] == nil)
    }

    private static func akp(algorithm: Int, pub: Data, kid: Data? = nil) -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [.int(1): .int(7), .int(3): .int(algorithm), .int(-1): .byteString(pub)]
        if let kid { map[.int(2)] = .byteString(kid) }
        return .map(map)
    }

    private static func authData(key: CBOR.Value) -> Data {
        Data(count: 32) + Data([0x41, 0, 0, 0, 1]) + Data(count: 16) + Data([0, 1, 1]) + key.encode()
    }
}
