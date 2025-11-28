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

import CryptoKit
import Foundation
import Testing

@testable import YubiKit

/// Test PIN/UV Auth Protocol v1 and v2 cryptographic operations.
///
/// Test vectors are shared with Java SDK (PinUvAuthProtocolV1Test.java, PinUvAuthProtocolV2Test.java).
@Suite("PinAuth Cryptographic Tests")
struct PinAuthTests {

    // MARK: - Protocol V1 Tests

    @Test("PinAuth V1: Encrypt - sequential bytes")
    func testV1EncryptSequential() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let plaintext = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let ciphertext = try pinProtocol.encrypt(key: key, plaintext: plaintext)
        let expected = Data([
            0x0a, 0x94, 0x0b, 0xb5, 0x41, 0x6e, 0xf0, 0x45,
            0xf1, 0xc3, 0x94, 0x58, 0xc6, 0x53, 0xea, 0x5a,
        ])
        #expect(ciphertext == expected)
    }

    @Test("PinAuth V1: Encrypt - zero bytes")
    func testV1EncryptZeros() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let plaintext = Data(repeating: 0x00, count: 16)
        let ciphertext = try pinProtocol.encrypt(key: key, plaintext: plaintext)
        let expected = Data([
            0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82,
            0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79,
        ])
        #expect(ciphertext == expected)
    }

    @Test("PinAuth V1: Decrypt - sequential bytes")
    func testV1DecryptSequential() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let ciphertext = Data([
            0x0a, 0x94, 0x0b, 0xb5, 0x41, 0x6e, 0xf0, 0x45,
            0xf1, 0xc3, 0x94, 0x58, 0xc6, 0x53, 0xea, 0x5a,
        ])
        let plaintext = try pinProtocol.decrypt(key: key, ciphertext: ciphertext)
        let expected = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        #expect(plaintext == expected)
    }

    @Test("PinAuth V1: Decrypt - zero bytes")
    func testV1DecryptZeros() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let ciphertext = Data([
            0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82,
            0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79,
        ])
        let plaintext = try pinProtocol.decrypt(key: key, ciphertext: ciphertext)
        let expected = Data(repeating: 0x00, count: 16)
        #expect(plaintext == expected)
    }

    @Test("PinAuth V1: Authenticate - sequential bytes (16-byte truncated HMAC)")
    func testV1AuthenticateSequential() {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let message = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let hmac = pinProtocol.authenticate(key: key, message: message)
        let expected = Data([
            0x9f, 0x3a, 0xa2, 0x88, 0x26, 0xb3, 0x74, 0x85,
            0xca, 0x05, 0x01, 0x4d, 0x71, 0x42, 0xb3, 0xea,
        ])
        #expect(hmac == expected)
        #expect(hmac.count == 16)
    }

    @Test("PinAuth V1: Authenticate - zero bytes")
    func testV1AuthenticateZeros() {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let key = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let message = Data(repeating: 0x00, count: 16)
        let hmac = pinProtocol.authenticate(key: key, message: message)
        let expected = Data([
            0xfe, 0x6e, 0x80, 0x16, 0xf7, 0xf2, 0x41, 0xc0,
            0x75, 0x65, 0xb4, 0x67, 0x68, 0x8e, 0x20, 0xc7,
        ])
        #expect(hmac == expected)
        #expect(hmac.count == 16)
    }

    // MARK: - Protocol V2 Tests

    @Test("PinAuth V2: Authenticate - sequential bytes (full 32-byte HMAC)")
    func testV2AuthenticateSequential() {
        let pinProtocol = PinAuth.ProtocolVersion.v2
        let hmacKey = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let key = hmacKey + Data(repeating: 0x00, count: 32)

        let message = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let hmac = pinProtocol.authenticate(key: key, message: message)
        let expected = Data([
            0x49, 0x5d, 0x46, 0xaa, 0x39, 0x2d, 0x51, 0x13,
            0x2e, 0xdb, 0x93, 0xbc, 0x49, 0xe6, 0x0e, 0xca,
            0xae, 0xb7, 0x80, 0x2f, 0x3a, 0xe5, 0x29, 0x77,
            0x9d, 0x58, 0x83, 0xf9, 0x33, 0x0a, 0xf5, 0x61,
        ])
        #expect(hmac == expected)
        #expect(hmac.count == 32)
    }

    @Test("PinAuth V2: Authenticate - zero bytes")
    func testV2AuthenticateZeros() {
        let pinProtocol = PinAuth.ProtocolVersion.v2
        let hmacKey = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let key = hmacKey + Data(repeating: 0x00, count: 32)

        let message = Data(repeating: 0x00, count: 16)
        let hmac = pinProtocol.authenticate(key: key, message: message)
        let expected = Data([
            0x7f, 0x0e, 0xa2, 0xb8, 0x05, 0x04, 0x89, 0x0f,
            0x3c, 0x6d, 0x42, 0xa7, 0x7e, 0x31, 0xc8, 0x33,
            0xe8, 0x81, 0xf7, 0x41, 0xd2, 0x12, 0x55, 0x69,
            0xac, 0x64, 0x27, 0xaa, 0x0c, 0x46, 0x6a, 0xad,
        ])
        #expect(hmac == expected)
        #expect(hmac.count == 32)
    }

    @Test("PinAuth V2: Encrypt/Decrypt roundtrip - sequential bytes")
    func testV2EncryptDecryptSequential() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v2
        let key = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let plaintext = Data([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])
        let ciphertext = try pinProtocol.encrypt(key: key, plaintext: plaintext)
        #expect(ciphertext.count == 32)  // 16-byte IV + 16-byte ciphertext

        let decrypted = try pinProtocol.decrypt(key: key, ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("PinAuth V2: Encrypt/Decrypt roundtrip - zero bytes")
    func testV2EncryptDecryptZeros() throws {
        let pinProtocol = PinAuth.ProtocolVersion.v2
        let key = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ])

        let plaintext = Data(repeating: 0x00, count: 16)
        let ciphertext = try pinProtocol.encrypt(key: key, plaintext: plaintext)
        #expect(ciphertext.count == 32)

        let decrypted = try pinProtocol.decrypt(key: key, ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    // MARK: - PIN Preparation and Validation

    @Test("preparePin without padding returns UTF-8 bytes")
    func testPreparePinWithoutPadding() throws {
        let prepared4 = try PinAuth.preparePin("1234", padded: false)
        #expect(prepared4 == Data([0x31, 0x32, 0x33, 0x34]))

        let prepared6 = try PinAuth.preparePin("foobar", padded: false)
        #expect(prepared6 == Data([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]))

        let pin63 = "123456789012345678901234567890123456789012345678901234567890123"
        let prepared63 = try PinAuth.preparePin(pin63, padded: false)
        #expect(prepared63.count == 63)
    }

    @Test("preparePin with padding returns 64 bytes")
    func testPreparePinWithPadding() throws {
        let prepared4 = try PinAuth.preparePin("1234", padded: true)
        #expect(prepared4.count == 64)
        #expect(prepared4.prefix(4) == Data([0x31, 0x32, 0x33, 0x34]))
        #expect(prepared4.suffix(60).allSatisfy { $0 == 0 })

        let prepared6 = try PinAuth.preparePin("foobar", padded: true)
        #expect(prepared6.count == 64)
        #expect(prepared6.prefix(6) == Data([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]))

        let pin63 = "123456789012345678901234567890123456789012345678901234567890123"
        let prepared63 = try PinAuth.preparePin(pin63, padded: true)
        #expect(prepared63.count == 64)
        #expect(prepared63[63] == 0)
    }

    @Test("preparePin rejects PIN shorter than 4 code points")
    func testPinTooShort() {
        #expect(throws: PinAuth.Error.pinTooShort) {
            _ = try PinAuth.preparePin("123", padded: false)
        }

        #expect(throws: PinAuth.Error.pinTooShort) {
            _ = try PinAuth.preparePin("123", padded: true)
        }
    }

    @Test("preparePin rejects PIN longer than 63 bytes")
    func testPinTooLong() {
        let pin64 = "1234567890123456789012345678901234567890123456789012345678901234"
        #expect(pin64.count == 64)

        #expect(throws: PinAuth.Error.pinTooLong) {
            _ = try PinAuth.preparePin(pin64, padded: false)
        }

        #expect(throws: PinAuth.Error.pinTooLong) {
            _ = try PinAuth.preparePin(pin64, padded: true)
        }
    }

    // MARK: - NFC Normalization

    @Test("preparePin normalizes to NFC - NFD input produces same bytes as NFC")
    func testNFCNormalization() throws {
        // "café" in NFC (precomposed): c a f é (4 code points)
        let nfc = "caf\u{00E9}"  // U+00E9 = é

        // "café" in NFD (decomposed): c a f e ́ (5 code points)
        let nfd = "cafe\u{0301}"  // U+0065 + U+0301 = e + combining acute

        // They look identical but have different raw bytes
        #expect(nfc.unicodeScalars.count == 4)
        #expect(nfd.unicodeScalars.count == 5)

        // After NFC normalization, both should produce identical bytes
        let preparedNFC = try PinAuth.preparePin(nfc, padded: false)
        let preparedNFD = try PinAuth.preparePin(nfd, padded: false)

        #expect(preparedNFC == preparedNFD)
        #expect(preparedNFC == Data([0x63, 0x61, 0x66, 0xc3, 0xa9]))  // UTF-8 for "café" in NFC
    }

    @Test("preparePin counts code points after NFC normalization")
    func testCodePointCountAfterNormalization() throws {
        // NFD "café" has 5 code points but NFC has 4
        let nfd = "cafe\u{0301}"
        #expect(nfd.unicodeScalars.count == 5)

        // Should still be valid (4 code points after normalization)
        let prepared = try PinAuth.preparePin(nfd, padded: false)
        #expect(prepared.count == 5)  // 5 UTF-8 bytes for "café"
    }

    @Test("preparePin rejects short PIN even with combining marks")
    func testShortPinWithCombiningMarks() {
        // "aé" in NFD: a e ́ (3 code points, but only 2 after NFC normalization)
        let nfd = "ae\u{0301}"
        #expect(nfd.unicodeScalars.count == 3)

        // After NFC normalization: "aé" = 2 code points, too short
        #expect(throws: PinAuth.Error.pinTooShort) {
            _ = try PinAuth.preparePin(nfd, padded: false)
        }
    }

    // MARK: - COSE Key

    @Test("coseKey produces valid P-256 COSE key from key pair")
    func testCoseKeyFromKeyPair() {
        let pinProtocol = PinAuth.ProtocolVersion.v1
        let keyPair = P256.KeyAgreement.PrivateKey()
        let coseKey = pinProtocol.coseKey(from: keyPair)

        guard case let .ec2(alg, _, crv, x, y) = coseKey else {
            Issue.record("Expected EC2 key")
            return
        }

        #expect(alg.rawValue == -25)  // ECDH-ES+HKDF-256
        #expect(crv == 1)  // P-256
        #expect(x.count == 32)
        #expect(y.count == 32)

        // Verify COSE key matches the original key pair
        var uncompressedPoint = Data([0x04])
        uncompressedPoint.append(x)
        uncompressedPoint.append(y)
        let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: uncompressedPoint)
        #expect(publicKey != nil)
        #expect(publicKey?.x963Representation == keyPair.publicKey.x963Representation)
    }
}
