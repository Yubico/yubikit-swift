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

import CommonCrypto
import Foundation
import Testing

@testable import YubiKit

/// Tests for EC key size, generation, encoding/decoding, and SecKey interoperability.
struct ECKeysTests {

    // MARK: - Curve Properties

    /// Test curve coordinate and key size properties.
    @Test func curveSizeProperties() {
        #expect(EC.Curve.p256.keySizeInBits == 256)
        #expect(EC.Curve.p384.keySizeInBits == 384)
        #expect(EC.Curve.p256.keySizeInBytes == 32)
        #expect(EC.Curve.p384.keySizeInBytes == 48)
    }

    // MARK: - Key Generation

    /// Test random EC private key generation and its properties.
    @Test func generateRandomPrivateKey() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let privKey = EC.PrivateKey.random(curve: curve)!
            #expect(privKey.publicKey.curve == curve)
            #expect(privKey.publicKey.x.count == curve.keySizeInBytes)
            #expect(privKey.publicKey.y.count == curve.keySizeInBytes)
            #expect(privKey.k.count == curve.keySizeInBytes)
        }
    }

    // MARK: - SecKey Conversion

    /// Test conversion from EC keys to SecKey.
    @Test func asSecKeyConversion() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let privKey = EC.PrivateKey.random(curve: curve)!
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
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            // Generate a random key
            let privKey = EC.PrivateKey.random(curve: curve)!

            // Encode to uncompressed representation
            let privRaw = privKey.uncompressedRepresentation
            let pubRaw = privKey.publicKey.uncompressedPoint

            // Decode back from uncompressed representation
            let decodedPriv = EC.PrivateKey(uncompressedRepresentation: privRaw)
            let decodedPub = EC.PublicKey(uncompressedPoint: pubRaw)

            // Compare all components of private key
            #expect(decodedPriv != nil)
            #expect(decodedPriv?.publicKey.x == privKey.publicKey.x)
            #expect(decodedPriv?.publicKey.y == privKey.publicKey.y)
            #expect(decodedPriv?.k == privKey.k)

            // Compare all components of public key
            #expect(decodedPub != nil)
            #expect(decodedPub?.x == privKey.publicKey.x)
            #expect(decodedPub?.y == privKey.publicKey.y)
        }
    }

    /// Test decoding of invalid representation returns nil.
    @Test func decodeInvalidRawReturnsNil() {
        let invalid = Data([0x00, 0x01, 0x02])
        let curves: [EC.Curve] = [.p256, .p384]
        for _ in curves {
            let decodedPriv = EC.PrivateKey(uncompressedRepresentation: invalid)
            #expect(decodedPriv == nil)
            let decodedPub = EC.PublicKey(uncompressedPoint: invalid)
            #expect(decodedPub == nil)
        }
    }

    // MARK: - Public Key SecKey Round Trip

    /// Test round-trip conversion from EC.PublicKey to SecKey and back, validating integrity.
    @Test func publicKeyToSecKeyAndBack() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let originalPrivKey = EC.PrivateKey.random(curve: curve)!
            let originalPubKey = originalPrivKey.publicKey

            let publicSecKey = try #require(originalPubKey.asSecKey())
            var error: Unmanaged<CFError>?
            let publicDERFromSecKey = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?
            #expect(publicDERFromSecKey != nil)

            // Re-initialize EC.PublicKey from this uncompressed data
            if let pubRaw = publicDERFromSecKey {
                let roundTrippedPubKey = EC.PublicKey(uncompressedPoint: pubRaw)
                #expect(roundTrippedPubKey != nil)
                #expect(roundTrippedPubKey?.x == originalPubKey.x)
                #expect(roundTrippedPubKey?.y == originalPubKey.y)
            }
        }
    }

    // MARK: - Private Key SecKey Round Trip

    /// Test round-trip conversion from EC.PrivateKey to SecKey and back, validating integrity.
    @Test func privateKeyToSecKeyAndBack() throws {
        let curves: [EC.Curve] = [.p256, .p384]
        for curve in curves {
            let originalPrivKey = EC.PrivateKey.random(curve: curve)!

            let privateSecKey = try #require(originalPrivKey.asSecKey())
            var error: Unmanaged<CFError>?
            let privateDERFromSecKey = SecKeyCopyExternalRepresentation(privateSecKey, &error) as Data?
            #expect(privateDERFromSecKey != nil)

            // Re-initialize EC.PrivateKey from this uncompressed data
            if let privRaw = privateDERFromSecKey {
                let roundTrippedPrivKey = EC.PrivateKey(uncompressedRepresentation: privRaw)
                #expect(roundTrippedPrivKey != nil)
                #expect(roundTrippedPrivKey?.publicKey.x == originalPrivKey.publicKey.x)
                #expect(roundTrippedPrivKey?.publicKey.y == originalPrivKey.publicKey.y)
                #expect(roundTrippedPrivKey?.k == originalPrivKey.k)
            }
        }
    }
}
