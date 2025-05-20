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

/// # ECKeysTests
/// Unit tests for the ECKeys implementation.
/// Validates key generation, encoding, decoding, SecKey conversions, and equality for EC keys.

import XCTest
import CommonCrypto

@testable import YubiKit

/// Tests for EC key size, generation, encoding/decoding, and SecKey interoperability.
final class ECKeysTests: XCTestCase {

    // MARK: - Curve Properties

    /// Test curve coordinate and key size properties.
    func testCurveSizeProperties() {
        XCTAssertEqual(EC.Curve.p256.keySizeInBits, 256)
        XCTAssertEqual(EC.Curve.p384.keySizeInBits, 384)
        XCTAssertEqual(EC.Curve.p256.keySizeInBytes, 32)
        XCTAssertEqual(EC.Curve.p384.keySizeInBytes, 48)
    }

    // MARK: - Key Generation

    /// Test random EC private key generation and its properties.
    func testGenerateRandomPrivateKey() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let privKey = EC.PrivateKey.random(curve: curve)!
            XCTAssertEqual(privKey.peer.curve, curve)
            XCTAssertEqual(privKey.peer.x.count, curve.keySizeInBytes)
            XCTAssertEqual(privKey.peer.y.count, curve.keySizeInBytes)
            XCTAssertEqual(privKey.k.count, curve.keySizeInBytes)
        }
    }

    // MARK: - SecKey Conversion

    /// Test conversion from EC keys to SecKey.
    func testAsSecKeyConversion() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let privKey = EC.PrivateKey.random(curve: curve)!
            let pubKey = privKey.peer

            let secPrivKey = privKey.asSecKey()
            let secPubKey = pubKey.asSecKey()
            XCTAssertNotNil(secPrivKey)
            XCTAssertNotNil(secPubKey)
        }
    }

    // MARK: - Encoding and Decoding

    /// End-to-end test of key generation, encoding, decoding, and comparison for all key components.
    func testRandomKeyGenerateEncodeDecodeCompare() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            // Generate a random key
            let privKey = EC.PrivateKey.random(curve: curve)!

            // Encode to uncompressed representation
            let privRaw = privKey.uncompressedRepresentation
            let pubRaw = privKey.peer.uncompressedRepresentation

            // Decode back from uncompressed representation
            let decodedPriv = EC.PrivateKey(uncompressedRepresentation: privRaw)
            let decodedPub = EC.PublicKey(uncompressedRepresentation: pubRaw)

            // Compare all components of private key
            XCTAssertNotNil(decodedPriv)
            XCTAssertEqual(decodedPriv?.peer.x, privKey.peer.x)
            XCTAssertEqual(decodedPriv?.peer.y, privKey.peer.y)
            XCTAssertEqual(decodedPriv?.k, privKey.k)

            // Compare all components of public key
            XCTAssertNotNil(decodedPub)
            XCTAssertEqual(decodedPub?.x, privKey.peer.x)
            XCTAssertEqual(decodedPub?.y, privKey.peer.y)
        }
    }

    /// Test decoding of invalid representation returns nil.
    func testDecodeInvalidRawReturnsNil() {
        let invalid = Data([0x00, 0x01, 0x02])
        let curves: [EC.Curve] = [.p256, .p384]
        for _ in curves {
            let decodedPriv = EC.PrivateKey(uncompressedRepresentation: invalid)
            XCTAssertNil(decodedPriv)
            let decodedPub = EC.PublicKey(uncompressedRepresentation: invalid)
            XCTAssertNil(decodedPub)
        }
    }

    // MARK: - Public Key SecKey Round Trip

    /// Test round-trip conversion from EC.PublicKey to SecKey and back, validating integrity.
    func testPublicKeyToSecKeyAndBack() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let originalPrivKey = EC.PrivateKey.random(curve: curve)!
            let originalPubKey = originalPrivKey.peer

            let publicSecKey = try XCTUnwrap(originalPubKey.asSecKey())
            var error: Unmanaged<CFError>?
            let publicDERFromSecKey = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?
            XCTAssertNotNil(publicDERFromSecKey)

            // Re-initialize EC.PublicKey from this uncompressed data
            if let pubRaw = publicDERFromSecKey {
                let roundTrippedPubKey = EC.PublicKey(uncompressedRepresentation: pubRaw)
                XCTAssertNotNil(roundTrippedPubKey)
                XCTAssertEqual(roundTrippedPubKey?.x, originalPubKey.x)
                XCTAssertEqual(roundTrippedPubKey?.y, originalPubKey.y)
            }
        }
    }

    // MARK: - Private Key SecKey Round Trip

    /// Test round-trip conversion from EC.PrivateKey to SecKey and back, validating integrity.
    func testPrivateKeyToSecKeyAndBack() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let originalPrivKey = EC.PrivateKey.random(curve: curve)!

            let privateSecKey = try XCTUnwrap(originalPrivKey.asSecKey())
            var error: Unmanaged<CFError>?
            let privateDERFromSecKey = SecKeyCopyExternalRepresentation(privateSecKey, &error) as Data?
            XCTAssertNotNil(privateDERFromSecKey)

            // Re-initialize EC.PrivateKey from this uncompressed data
            if let privRaw = privateDERFromSecKey {
                let roundTrippedPrivKey = EC.PrivateKey(uncompressedRepresentation: privRaw)
                XCTAssertNotNil(roundTrippedPrivKey)
                XCTAssertEqual(roundTrippedPrivKey?.peer.x, originalPrivKey.peer.x)
                XCTAssertEqual(roundTrippedPrivKey?.peer.y, originalPrivKey.peer.y)
                XCTAssertEqual(roundTrippedPrivKey?.k, originalPrivKey.k)
            }
        }
    }
}
