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

/// # RSAKeysTests
/// Unit tests for the RSAKeys implementation.
/// Validates key generation, encoding, decoding, SecKey conversions, and equality for RSA keys.

import CommonCrypto
import XCTest

@testable import YubiKit

/// Tests for RSA key size, generation, encoding/decoding, and SecKey interoperability.
final class RSAKeysTests: XCTestCase {

    // MARK: - Key Size Properties

    /// Test basic key size properties for RSA.KeySize.
    func testKeySizeProperties() {
        XCTAssertEqual(RSA.KeySize.bits1024.keySizeInBits, 1024)
        XCTAssertEqual(RSA.KeySize.bits2048.keySizeInBits, 2048)
        XCTAssertEqual(RSA.KeySize.bits4096.keySizeInBytes, 4096 / 8)
    }

    // MARK: - Key Generation

    /// Test random RSA private key generation and its properties.
    func testGenerateRandomPrivateKey() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            let privKey = RSA.PrivateKey.random(keySize: keySize)
            XCTAssertNotNil(privKey)
            XCTAssertEqual(privKey?.publicKey.size, keySize)
            XCTAssertEqual(privKey?.publicKey.n.count, keySize.keySizeInBytes)
        }
    }

    // MARK: - SecKey Conversion

    /// Test conversion from RSA keys to SecKey.
    func testAsSecKeyConversion() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            let privKey = RSA.PrivateKey.random(keySize: keySize)!
            let pubKey = privKey.publicKey

            let secPrivKey = privKey.asSecKey()
            let secPubKey = pubKey.asSecKey()
            XCTAssertNotNil(secPrivKey)
            XCTAssertNotNil(secPubKey)
        }
    }

    // MARK: - Encoding and Decoding

    /// End-to-end test of key generation, encoding, decoding, and comparison for all key components.
    func testRandomKeyGenerateEncodeDecodeCompare() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            // Generate a random key
            let privKey = try XCTUnwrap(RSA.PrivateKey.random(keySize: keySize))

            // Encode to PKCS#1 DER
            let privDER = privKey.pkcs1
            let pubDER = privKey.publicKey.pkcs1

            // Decode back from DER
            let decodedPriv = try XCTUnwrap(RSA.PrivateKey(pkcs1: privDER))
            let decodedPub = try XCTUnwrap(RSA.PublicKey(pkcs1: pubDER))

            // Compare all components of private key
            XCTAssertEqual(decodedPriv.n, privKey.n)
            XCTAssertEqual(decodedPriv.d, privKey.d)
            XCTAssertEqual(decodedPriv.p, privKey.p)
            XCTAssertEqual(decodedPriv.q, privKey.q)
            XCTAssertEqual(decodedPriv.dP, privKey.dP)
            XCTAssertEqual(decodedPriv.dQ, privKey.dQ)
            XCTAssertEqual(decodedPriv.qInv, privKey.qInv)

            // Compare all components of public key
            XCTAssertEqual(decodedPub.n, privKey.publicKey.n)
            XCTAssertEqual(decodedPub.e, privKey.publicKey.e)

            // Also check the public key inside decoded private key
            XCTAssertEqual(decodedPriv.publicKey.n, privKey.publicKey.n)
            XCTAssertEqual(decodedPriv.publicKey.e, privKey.publicKey.e)
            XCTAssertEqual(decodedPriv.publicKey.size, privKey.publicKey.size)
        }
    }

    /// Test decoding of invalid DER data returns nil.
    func testDecodeInvalidDERReturnsNil() {
        let invalidDER = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for _ in keySizes {
            let decodedPriv = RSA.PrivateKey(pkcs1: invalidDER)
            XCTAssertNil(decodedPriv)
            let decodedPub = RSA.PublicKey(pkcs1: invalidDER)
            XCTAssertNil(decodedPub)
        }
    }

    // MARK: - Public Key SecKey Round Trip

    /// Test round-trip conversion from RSA.PublicKey to SecKey and back, validating integrity.
    func testPublicKeyToSecKeyAndBack() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]

        for keySize in keySizes {
            // Generate RSA.PrivateKey to get a public key
            let originalPrivKey = try XCTUnwrap(RSA.PrivateKey.random(keySize: keySize))
            let originalPubKey = originalPrivKey.publicKey

            // Convert RSA.PublicKey to SecKey
            let publicSecKey = try XCTUnwrap(originalPubKey.asSecKey())

            // Extract PKCS#1 data from public SecKey
            var error: Unmanaged<CFError>?
            let publicDERFromSecKey = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?)

            // Re-initialize RSA.PublicKey from this PKCS#1 data
            let roundTrippedPubKey = try XCTUnwrap(RSA.PublicKey(pkcs1: publicDERFromSecKey))

            // Compare
            XCTAssertEqual(roundTrippedPubKey.n, originalPubKey.n)
            XCTAssertEqual(roundTrippedPubKey.e, originalPubKey.e)
            XCTAssertEqual(roundTrippedPubKey.size, originalPubKey.size)
        }
    }

    // MARK: - Private Key SecKey Round Trip

    /// Test round-trip conversion from RSA.PrivateKey to SecKey and back, validating integrity.
    func testPrivateKeyToSecKeyAndBack() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]

        for keySize in keySizes {
            // Generate RSA.PrivateKey
            let originalPrivKey = try XCTUnwrap(RSA.PrivateKey.random(keySize: keySize))

            // Convert RSA.PrivateKey to SecKey
            let privateSecKey = try XCTUnwrap(originalPrivKey.asSecKey())

            // Extract PKCS#1 data from private SecKey
            var error: Unmanaged<CFError>?
            let privateDERFromSecKey = try XCTUnwrap(SecKeyCopyExternalRepresentation(privateSecKey, &error) as Data?)

            // Re-initialize RSA.PrivateKey from this PKCS#1 data
            let roundTrippedPrivKey = try XCTUnwrap(RSA.PrivateKey(pkcs1: privateDERFromSecKey))

            // Compare
            XCTAssertEqual(roundTrippedPrivKey.n, originalPrivKey.n)
            XCTAssertEqual(roundTrippedPrivKey.d, originalPrivKey.d)
            XCTAssertEqual(roundTrippedPrivKey.p, originalPrivKey.p)
            XCTAssertEqual(roundTrippedPrivKey.q, originalPrivKey.q)
            XCTAssertEqual(roundTrippedPrivKey.dP, originalPrivKey.dP)
            XCTAssertEqual(roundTrippedPrivKey.dQ, originalPrivKey.dQ)
            XCTAssertEqual(roundTrippedPrivKey.qInv, originalPrivKey.qInv)
            XCTAssertEqual(roundTrippedPrivKey.publicKey.e, originalPrivKey.publicKey.e)
            XCTAssertEqual(roundTrippedPrivKey.size, originalPrivKey.size)
        }
    }
}
