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

struct HashingPlusKDFTests {

    // MARK: - Hash Functions

    @Test func sha1Hash() {
        let data = "abc".data(using: .utf8)!
        let hash = data.sha1()
        #expect(hash.hexEncodedString == "a9993e364706816aba3e25717850c26c9cd0d89d")
    }

    @Test func sha224Hash() {
        let data = "abc".data(using: .utf8)!
        let hash = data.sha224()
        #expect(hash.hexEncodedString == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
    }

    @Test func sha256Hash() {
        let data = "abc".data(using: .utf8)!
        let hash = data.sha256()
        #expect(hash.hexEncodedString == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func sha384Hash() {
        let data = "abc".data(using: .utf8)!
        let hash = data.sha384()
        #expect(
            hash.hexEncodedString
                == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
    }

    @Test func sha512Hash() {
        let data = "abc".data(using: .utf8)!
        let hash = data.sha512()
        #expect(
            hash.hexEncodedString
                == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    // MARK: - HMAC

    @Test func hmacSha1() {
        let key = Data(repeating: 0x0b, count: 20)
        let data = "Hi There".data(using: .utf8)!
        let mac = data.hmacSha1(key: key)
        #expect(mac.hexEncodedString == "b617318655057264e28bc0b6fb378c8ef146be00")
    }

    @Test func hmacSha256() {
        let key = Data(repeating: 0x0b, count: 20)
        let data = "Hi There".data(using: .utf8)!
        let mac = data.hmacSha256(key: key)
        #expect(mac.hexEncodedString == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }

    // MARK: - HKDF

    @Test func hkdfDerivation() {
        // RFC 5869 Test Case 1 (truncated to 32 bytes)
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = Data(hexEncodedString: "000102030405060708090a0b0c")!
        let info = Data(hexEncodedString: "f0f1f2f3f4f5f6f7f8f9")!
        let derived = ikm.hkdfDeriveKey(salt: salt, info: info, outputByteCount: 32)
        #expect(derived.hexEncodedString == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    }

    // MARK: - PBKDF2

    @Test func pbkdf2Derivation() throws {
        let derived = try Data.pbkdf2(
            password: "password",
            salt: "salt".data(using: .utf8)!,
            iterations: 1,
            keyLength: 20
        )
        #expect(derived.hexEncodedString == "0c60c80f961f0e71f3a9b524af6012062fe037a6")
    }

    // MARK: - Random

    @Test func randomGeneration() throws {
        let random = try Data.random(length: 32)
        #expect(random.count == 32)
        #expect(random != Data(count: 32))  // Not all zeros
    }

    @Test func randomUniqueness() throws {
        let r1 = try Data.random(length: 16)
        let r2 = try Data.random(length: 16)
        #expect(r1 != r2)
    }

    // MARK: - Constant Time Compare

    @Test func constantTimeCompareEqual() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(a.constantTimeCompare(b) == true)
    }

    @Test func constantTimeCompareNotEqual() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x05])
        #expect(a.constantTimeCompare(b) == false)
    }

    @Test func constantTimeCompareDifferentLength() {
        let a = Data([0x01, 0x02, 0x03])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(a.constantTimeCompare(b) == false)
    }
}
