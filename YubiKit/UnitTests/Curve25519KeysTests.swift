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

// Tests for Ed25519 and X25519 key handling and validation.
struct Curve25519KeysTests {

    // MARK: - Ed25519 Tests

    // Test Ed25519 public key creation with valid data.
    @Test func ed25519PublicKeyValidData() {
        // Generate a valid Ed25519 key pair using CryptoKit
        let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
        let validKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = Ed25519.PublicKey(keyData: validKeyData)

        #expect(publicKey != nil)
        #expect(publicKey?.keyData == validKeyData)
        #expect(publicKey?.keyData.count == 32)
    }

    // Test Ed25519 public key creation with invalid data.
    @Test func ed25519PublicKeyInvalidData() {
        let invalidKeyData31 = Data(repeating: 0x01, count: 31)
        let invalidKeyData33 = Data(repeating: 0x01, count: 33)
        let emptyData = Data()

        #expect(Ed25519.PublicKey(keyData: invalidKeyData31) == nil)
        #expect(Ed25519.PublicKey(keyData: invalidKeyData33) == nil)
        #expect(Ed25519.PublicKey(keyData: emptyData) == nil)
    }

    // Test Ed25519 private key creation with valid data.
    @Test func ed25519PrivateKeyValidData() {
        // Generate a valid Ed25519 key pair using CryptoKit
        let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
        let validSeed = cryptoKitPrivateKey.rawRepresentation
        let validPublicKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = Ed25519.PublicKey(keyData: validPublicKeyData)!

        let privateKey = Ed25519.PrivateKey(seed: validSeed, publicKey: publicKey)

        #expect(privateKey != nil)
        #expect(privateKey?.seed == validSeed)
        #expect(privateKey?.publicKey == publicKey)
        #expect(privateKey?.seed.count == 32)
    }

    // Test Ed25519 private key creation with invalid data.
    @Test func ed25519PrivateKeyInvalidData() {
        let invalidSeed31 = Data(repeating: 0x02, count: 31)
        let invalidSeed33 = Data(repeating: 0x02, count: 33)
        // Generate a valid public key for testing
        let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
        let validPublicKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = Ed25519.PublicKey(keyData: validPublicKeyData)!

        #expect(Ed25519.PrivateKey(seed: invalidSeed31, publicKey: publicKey) == nil)
        #expect(Ed25519.PrivateKey(seed: invalidSeed33, publicKey: publicKey) == nil)
    }

    // MARK: - X25519 Tests

    // Test X25519 public key creation with valid data.
    @Test func x25519PublicKeyValidData() {
        // Generate a valid X25519 key pair using CryptoKit
        let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let validKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = X25519.PublicKey(keyData: validKeyData)

        #expect(publicKey != nil)
        #expect(publicKey?.keyData == validKeyData)
        #expect(publicKey?.keyData.count == 32)
    }

    // Test X25519 public key creation with invalid data.
    @Test func x25519PublicKeyInvalidData() {
        let invalidKeyData31 = Data(repeating: 0x04, count: 31)
        let invalidKeyData33 = Data(repeating: 0x04, count: 33)
        let emptyData = Data()

        #expect(X25519.PublicKey(keyData: invalidKeyData31) == nil)
        #expect(X25519.PublicKey(keyData: invalidKeyData33) == nil)
        #expect(X25519.PublicKey(keyData: emptyData) == nil)
    }

    // Test X25519 private key creation with valid data.
    @Test func x25519PrivateKeyValidData() {
        // Generate a valid X25519 key pair using CryptoKit
        let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let validScalar = cryptoKitPrivateKey.rawRepresentation
        let validPublicKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = X25519.PublicKey(keyData: validPublicKeyData)!

        let privateKey = X25519.PrivateKey(scalar: validScalar, publicKey: publicKey)

        #expect(privateKey != nil)
        #expect(privateKey?.scalar == validScalar)
        #expect(privateKey?.publicKey == publicKey)
        #expect(privateKey?.scalar.count == 32)
    }

    // Test X25519 private key creation with invalid data.
    @Test func x25519PrivateKeyInvalidData() {
        let invalidScalar31 = Data(repeating: 0x05, count: 31)
        let invalidScalar33 = Data(repeating: 0x05, count: 33)
        // Generate a valid public key for testing
        let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let validPublicKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
        let publicKey = X25519.PublicKey(keyData: validPublicKeyData)!

        #expect(X25519.PrivateKey(scalar: invalidScalar31, publicKey: publicKey) == nil)
        #expect(X25519.PrivateKey(scalar: invalidScalar33, publicKey: publicKey) == nil)
    }

    // MARK: - Equality Tests

    // Test Ed25519 key equality.
    @Test func ed25519KeyEquality() {
        let keyData1 = Data(repeating: 0x07, count: 32)
        let keyData2 = Data(repeating: 0x08, count: 32)

        let publicKey1a = Ed25519.PublicKey(keyData: keyData1)!
        let publicKey1b = Ed25519.PublicKey(keyData: keyData1)!
        let publicKey2 = Ed25519.PublicKey(keyData: keyData2)!

        #expect(publicKey1a == publicKey1b)
        #expect(publicKey1a != publicKey2)
    }

    // Test X25519 key equality.
    @Test func x25519KeyEquality() {
        let keyData1 = Data(repeating: 0x09, count: 32)
        let keyData2 = Data(repeating: 0x0A, count: 32)

        let publicKey1a = X25519.PublicKey(keyData: keyData1)!
        let publicKey1b = X25519.PublicKey(keyData: keyData1)!
        let publicKey2 = X25519.PublicKey(keyData: keyData2)!

        #expect(publicKey1a == publicKey1b)
        #expect(publicKey1a != publicKey2)
    }
}
