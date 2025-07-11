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
import Foundation
import Testing

@testable import YubiKit

/// Tests for RSA key size, generation, encoding/decoding, and SecKey interoperability.
struct RSAKeysTests {

    // MARK: - Key Size Properties

    /// Test basic key size properties for RSA.KeySize.
    @Test func keySizeProperties() {
        #expect(RSA.KeySize.bits1024.keySizeInBits == 1024)
        #expect(RSA.KeySize.bits2048.keySizeInBits == 2048)
        #expect(RSA.KeySize.bits4096.keySizeInBytes == 4096 / 8)
    }

    // MARK: - Key Generation

    /// Test random RSA private key generation and its properties.
    @Test func generateRandomPrivateKey() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            let privKey = RSA.PrivateKey.random(keySize: keySize)
            #expect(privKey != nil)
            #expect(privKey?.publicKey.size == keySize)
            #expect(privKey?.publicKey.n.count == keySize.keySizeInBytes)
        }
    }

    // MARK: - SecKey Conversion

    /// Test conversion from RSA keys to SecKey.
    @Test func asSecKeyConversion() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            let privKey = RSA.PrivateKey.random(keySize: keySize)!
            let pubKey = privKey.publicKey

            let secPrivKey = privKey.asSecKey()
            let secPubKey = pubKey.asSecKey()
            #expect(secPrivKey != nil)
            #expect(secPubKey != nil)
        }
    }

    // MARK: - Encoding and Decoding

    /// End-to-end test of key generation, encoding, decoding, and comparison for all key components.
    @Test func randomKeyGenerateEncodeDecodeCompare() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for keySize in keySizes {
            // Generate a random key
            let privKey = try #require(RSA.PrivateKey.random(keySize: keySize))

            // Encode to PKCS#1 DER
            let privDER = privKey.pkcs1
            let pubDER = privKey.publicKey.pkcs1

            // Decode back from DER
            let decodedPriv = try #require(RSA.PrivateKey(pkcs1: privDER))
            let decodedPub = try #require(RSA.PublicKey(pkcs1: pubDER))

            // Compare all components of private key
            #expect(decodedPriv.n == privKey.n)
            #expect(decodedPriv.d == privKey.d)
            #expect(decodedPriv.p == privKey.p)
            #expect(decodedPriv.q == privKey.q)
            #expect(decodedPriv.dP == privKey.dP)
            #expect(decodedPriv.dQ == privKey.dQ)
            #expect(decodedPriv.qInv == privKey.qInv)

            // Compare all components of public key
            #expect(decodedPub.n == privKey.publicKey.n)
            #expect(decodedPub.e == privKey.publicKey.e)

            // Also check the public key inside decoded private key
            #expect(decodedPriv.publicKey.n == privKey.publicKey.n)
            #expect(decodedPriv.publicKey.e == privKey.publicKey.e)
            #expect(decodedPriv.publicKey.size == privKey.publicKey.size)
        }
    }

    /// Test decoding of invalid DER data returns nil.
    @Test func decodeInvalidDERReturnsNil() {
        let invalidDER = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]
        for _ in keySizes {
            let decodedPriv = RSA.PrivateKey(pkcs1: invalidDER)
            #expect(decodedPriv == nil)
            let decodedPub = RSA.PublicKey(pkcs1: invalidDER)
            #expect(decodedPub == nil)
        }
    }

    // MARK: - Public Key SecKey Round Trip

    /// Test round-trip conversion from RSA.PublicKey to SecKey and back, validating integrity.
    @Test func publicKeyToSecKeyAndBack() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]

        for keySize in keySizes {
            // Generate RSA.PrivateKey to get a public key
            let originalPrivKey = try #require(RSA.PrivateKey.random(keySize: keySize))
            let originalPubKey = originalPrivKey.publicKey

            // Convert RSA.PublicKey to SecKey
            let publicSecKey = try #require(originalPubKey.asSecKey())

            // Extract PKCS#1 data from public SecKey
            var error: Unmanaged<CFError>?
            let publicDERFromSecKey = try #require(SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?)

            // Re-initialize RSA.PublicKey from this PKCS#1 data
            let roundTrippedPubKey = try #require(RSA.PublicKey(pkcs1: publicDERFromSecKey))

            // Compare
            #expect(roundTrippedPubKey.n == originalPubKey.n)
            #expect(roundTrippedPubKey.e == originalPubKey.e)
            #expect(roundTrippedPubKey.size == originalPubKey.size)
        }
    }

    // MARK: - Private Key SecKey Round Trip

    /// Test round-trip conversion from RSA.PrivateKey to SecKey and back, validating integrity.
    @Test func privateKeyToSecKeyAndBack() throws {
        let keySizes: [RSA.KeySize] = [.bits1024, .bits2048, .bits4096]

        for keySize in keySizes {
            // Generate RSA.PrivateKey
            let originalPrivKey = try #require(RSA.PrivateKey.random(keySize: keySize))

            // Convert RSA.PrivateKey to SecKey
            let privateSecKey = try #require(originalPrivKey.asSecKey())

            // Extract PKCS#1 data from private SecKey
            var error: Unmanaged<CFError>?
            let privateDERFromSecKey = try #require(SecKeyCopyExternalRepresentation(privateSecKey, &error) as Data?)

            // Re-initialize RSA.PrivateKey from this PKCS#1 data
            let roundTrippedPrivKey = try #require(RSA.PrivateKey(pkcs1: privateDERFromSecKey))

            // Compare
            #expect(roundTrippedPrivKey.n == originalPrivKey.n)
            #expect(roundTrippedPrivKey.d == originalPrivKey.d)
            #expect(roundTrippedPrivKey.p == originalPrivKey.p)
            #expect(roundTrippedPrivKey.q == originalPrivKey.q)
            #expect(roundTrippedPrivKey.dP == originalPrivKey.dP)
            #expect(roundTrippedPrivKey.dQ == originalPrivKey.dQ)
            #expect(roundTrippedPrivKey.qInv == originalPrivKey.qInv)
            #expect(roundTrippedPrivKey.publicKey.e == originalPrivKey.publicKey.e)
            #expect(roundTrippedPrivKey.size == originalPrivKey.size)
        }
    }
}
