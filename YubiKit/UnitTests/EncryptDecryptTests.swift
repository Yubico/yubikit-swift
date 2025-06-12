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

import CommonCrypto
import Foundation
import Testing

@testable import YubiKit

struct EncryptDecryptTests {

    @Test func encryptAESECB() throws {
        let data = "Hello World!0000".data(using: .utf8)!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a729439158766cfee5497c2b")!
        let result = try data.encrypt(algorithm: UInt32(kCCAlgorithmAES), key: key)
        let expected = Data(hexEncodedString: "0cb774fc5a0a3d4fbb9a6b582cb56b84")!
        #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
    }

    @Test func decryptAESECB() throws {
        let data = Data(
            hexEncodedString:
                "0cb774fc5a0a3d4fbb9a6b582cb56b84fa4e95678dbb6cc763bb4ce68df9155ffa4e95678dbb6cc763bb4ce68df9155ffa4e95678dbb6cc763bb4ce68df9155f"
        )!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a729439158766cfee5497c2b")!
        let result = try data.decrypt(algorithm: UInt32(kCCAlgorithmAES), key: key)
        let decrypted = String(data: result, encoding: .utf8)!
        let expected = "Hello World!0000000000000000000000000000000000000000000000000000"
        #expect(decrypted == expected, "Got \(decrypted), expected: \(expected)")
    }

    @Test func encryptAESCBC() throws {
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f842049")!
        let iv = Data(hexEncodedString: "000102030405060708090a0b0c0d0e0f")!
        let data = "Hello World!0000".data(using: .utf8)!
        let encrypted = try data.encrypt(algorithm: UInt32(kCCAlgorithmAES), key: key, iv: iv)
        #expect(encrypted == Data(hexEncodedString: "9dcb09c51227ea753fad4c6bda8efa46")!)
    }

    @Test func decryptAESCBC() throws {
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f842049")!
        let iv = Data(hexEncodedString: "000102030405060708090a0b0c0d0e0f")!
        let encrypted = Data(hexEncodedString: "9dcb09c51227ea753fad4c6bda8efa46")!
        let decrypted = try encrypted.decrypt(algorithm: UInt32(kCCAlgorithmAES), key: key, iv: iv)
        let plainText = String(data: decrypted, encoding: .utf8)
        #expect(
            plainText == "Hello World!0000",
            "Got \(String(describing: plainText)), expected: \"Hello World!0000\""
        )
    }

    @Test func encrypt3DES() throws {
        let data = "Hello World!0000".data(using: .utf8)!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a7294391")!
        let result = try data.encrypt(algorithm: UInt32(kCCAlgorithm3DES), key: key)
        let expected = Data(hexEncodedString: "b2b1619cecc9e1b2fba580d764af2c43")!
        #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
    }

    @Test func decrypt3DES() throws {
        let data = Data(hexEncodedString: "b2b1619cecc9e1b2fba580d764af2c43")!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a7294391")!
        let result = try data.decrypt(algorithm: UInt32(kCCAlgorithm3DES), key: key)
        let decrypted = String(data: result, encoding: .utf8)!
        let expected = "Hello World!0000"
        #expect(decrypted == expected, "Got \(decrypted), expected: \(expected)")
    }

    @Test func aescmac0() throws {
        let key = Data(hexEncodedString: "2b7e1516 28aed2a6 abf71588 09cf4f3c")!
        let msg = Data()
        let expectedMac = Data(hexEncodedString: "bb1d6929 e9593728 7fa37d12 9b756746")!
        let result = try msg.aescmac(key: key)
        #expect(result == expectedMac)
    }

    @Test func aescmac16() throws {
        let key = Data(hexEncodedString: "2b7e1516 28aed2a6 abf71588 09cf4f3c")!
        let msg = Data(hexEncodedString: "6bc1bee2 2e409f96 e93d7e11 7393172a")!
        let expectedMac = Data(hexEncodedString: "070a16b4 6b4d4144 f79bdd9d d04a287c")!
        let result = try msg.aescmac(key: key)
        #expect(result == expectedMac)
    }

    @Test func aescmac40() throws {
        let key = Data(hexEncodedString: "2b7e1516 28aed2a6 abf71588 09cf4f3c")!
        let msg = Data(
            hexEncodedString:
                "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411"
        )!
        let expectedMac = Data(hexEncodedString: "dfa66747 de9ae630 30ca3261 1497c827")!
        let result = try msg.aescmac(key: key)
        #expect(result == expectedMac)
    }

    @Test func aescmac64() throws {
        let key = Data(hexEncodedString: "2b7e1516 28aed2a6 abf71588 09cf4f3c")!
        let msg = Data(
            hexEncodedString:
                "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710"
        )!
        let expectedMac = Data(hexEncodedString: "51f0bebf 7e3b9d92 fc497417 79363cfe")!
        let result = try msg.aescmac(key: key)
        #expect(result == expectedMac)
    }

}
