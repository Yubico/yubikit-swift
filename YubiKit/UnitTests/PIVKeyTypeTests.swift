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

/// # PIVKeyTypeTests
/// Unit tests for PIVKeyType enum, including Ed25519 and X25519 support.
/// Validates algorithm identifiers, conversions, and key size properties.

import Foundation
import Testing

@testable import YubiKit

/// Tests for PIVKeyType enum with Ed25519 and X25519 support.
struct PIVKeyTypeTests {

    // MARK: - Algorithm Identifier Tests

    /// Test Ed25519 algorithm identifier.
    @Test func ed25519AlgorithmIdentifier() {
        let keyType = PIVKeyType.ed25519
        #expect(keyType.rawValue == 0xE0)
    }

    /// Test X25519 algorithm identifier.
    @Test func x25519AlgorithmIdentifier() {
        let keyType = PIVKeyType.x25519
        #expect(keyType.rawValue == 0xE1)
    }

    /// Test creating PIVKeyType from Ed25519 raw value.
    @Test func createEd25519FromRawValue() {
        let keyType = PIVKeyType(rawValue: 0xE0)
        #expect(keyType == .ed25519)
    }

    /// Test creating PIVKeyType from X25519 raw value.
    @Test func createX25519FromRawValue() {
        let keyType = PIVKeyType(rawValue: 0xE1)
        #expect(keyType == .x25519)
    }

    /// Test creating PIVKeyType from invalid raw value.
    @Test func createFromInvalidRawValue() {
        let keyType = PIVKeyType(rawValue: 0xFF)
        #expect(keyType == nil)
    }

    // MARK: - Key Size Tests

    /// Test Ed25519 key size in bits.
    @Test func ed25519KeySizeInBits() {
        let keyType = PIVKeyType.ed25519
        #expect(keyType.sizeInBits == 256)
    }

    /// Test X25519 key size in bits.
    @Test func x25519KeySizeInBits() {
        let keyType = PIVKeyType.x25519
        #expect(keyType.sizeInBits == 256)
    }

    /// Test Ed25519 key size in bytes.
    @Test func ed25519KeySizeInBytes() {
        let keyType = PIVKeyType.ed25519
        #expect(keyType.sizeInBytes == 32)
    }

    /// Test X25519 key size in bytes.
    @Test func x25519KeySizeInBytes() {
        let keyType = PIVKeyType.x25519
        #expect(keyType.sizeInBytes == 32)
    }

    // MARK: - CryptoKeyKind Conversion Tests

    /// Test creating PIVKeyType from Ed25519 CryptoKeyKind.
    @Test func createFromEd25519CryptoKeyKind() {
        let keyType = PIVKeyType(kind: .ed25519)
        #expect(keyType == .ed25519)
    }

    /// Test creating PIVKeyType from X25519 CryptoKeyKind.
    @Test func createFromX25519CryptoKeyKind() {
        let keyType = PIVKeyType(kind: .x25519)
        #expect(keyType == .x25519)
    }

    // MARK: - Equality Tests

    /// Test Ed25519 key type equality.
    @Test func ed25519Equality() {
        let keyType1 = PIVKeyType.ed25519
        let keyType2 = PIVKeyType.ed25519
        let keyType3 = PIVKeyType.x25519

        #expect(keyType1 == keyType2)
        #expect(keyType1 != keyType3)
    }

    /// Test X25519 key type equality.
    @Test func x25519Equality() {
        let keyType1 = PIVKeyType.x25519
        let keyType2 = PIVKeyType.x25519
        let keyType3 = PIVKeyType.ed25519

        #expect(keyType1 == keyType2)
        #expect(keyType1 != keyType3)
    }

    // MARK: - Comprehensive Algorithm Identifier Tests

    /// Test all existing algorithm identifiers remain unchanged.
    @Test func existingAlgorithmIdentifiers() {
        #expect(PIVKeyType.rsa(.bits1024).rawValue == 0x06)
        #expect(PIVKeyType.rsa(.bits2048).rawValue == 0x07)
        #expect(PIVKeyType.rsa(.bits3072).rawValue == 0x05)
        #expect(PIVKeyType.rsa(.bits4096).rawValue == 0x16)
        #expect(PIVKeyType.ecc(.p256).rawValue == 0x11)
        #expect(PIVKeyType.ecc(.p384).rawValue == 0x14)
    }

    /// Test creating all PIVKeyType variants from their raw values.
    @Test func allRawValueConversions() {
        let testCases: [(UInt8, PIVKeyType?)] = [
            (0x06, .rsa(.bits1024)),
            (0x07, .rsa(.bits2048)),
            (0x05, .rsa(.bits3072)),
            (0x16, .rsa(.bits4096)),
            (0x11, .ecc(.p256)),
            (0x14, .ecc(.p384)),
            (0xE0, .ed25519),
            (0xE1, .x25519),
            (0xFF, nil),
        ]

        for (rawValue, expectedType) in testCases {
            let actualType = PIVKeyType(rawValue: rawValue)
            #expect(
                actualType == expectedType,
                "Failed for raw value 0x\(String(rawValue, radix: 16, uppercase: true))"
            )
        }
    }
}
