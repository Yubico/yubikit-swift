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

// # ECKeysTests
// Unit tests for the ECKeys implementation.
// Validates key generation, encoding/decoding, and equality for EC keys.

import Foundation
import Testing

@testable import YubiKit

// Tests for EC key size, generation, and encoding/decoding.
struct ECKeysTests {

    // MARK: - Curve Properties

    // Test curve coordinate and key size properties.
    @Test func curveSizeProperties() {
        #expect(EC.Curve.secp256r1.keySizeInBits == 256)
        #expect(EC.Curve.secp384r1.keySizeInBits == 384)
        #expect(EC.Curve.secp256r1.keySizeInBytes == 32)
        #expect(EC.Curve.secp384r1.keySizeInBytes == 48)
    }

    // MARK: - Key Generation

    // Test random EC private key generation and its properties.
    @Test func generateRandomPrivateKey() throws {
        let curves: [EC.Curve] = [.secp256r1, .secp384r1]
        for curve in curves {
            let privKey = try EC.PrivateKey.random(curve: curve)
            #expect(privKey.publicKey.curve == curve)
            #expect(privKey.publicKey.x.count == curve.keySizeInBytes)
            #expect(privKey.publicKey.y.count == curve.keySizeInBytes)
            #expect(privKey.k.count == curve.keySizeInBytes)
        }
    }

    // MARK: - Encoding and Decoding

    // End-to-end test of key generation, encoding, decoding, and comparison for all key components.
    @Test func randomKeyGenerateEncodeDecodeCompare() throws {
        let curves: [EC.Curve] = [.secp256r1, .secp384r1]
        for curve in curves {
            // Generate a random key
            let privKey = try EC.PrivateKey.random(curve: curve)

            // Encode to X9.63 representation
            let privX963 = privKey.x963Representation
            let pubX963 = privKey.publicKey.x963Representation

            // Decode back from X9.63 representation
            let decodedPriv = EC.PrivateKey(x963Representation: privX963, curve: curve)
            let decodedPub = EC.PublicKey(x963Representation: pubX963, curve: curve)

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

    // Test decoding of invalid representation returns nil.
    @Test func decodeInvalidRawReturnsNil() {
        let invalid = Data([0x00, 0x01, 0x02])
        let curves: [EC.Curve] = [.secp256r1, .secp384r1]
        for curve in curves {
            let decodedPriv = EC.PrivateKey(x963Representation: invalid, curve: curve)
            #expect(decodedPriv == nil)
            let decodedPub = EC.PublicKey(x963Representation: invalid, curve: curve)
            #expect(decodedPub == nil)
        }
    }
}
