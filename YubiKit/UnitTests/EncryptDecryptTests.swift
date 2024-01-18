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

import XCTest
import YubiKit
import CommonCrypto

final class EncryptDecryptTests: XCTestCase {
    
    func testEncryptAES() throws {
        let data = "Hello World!0000".data(using: .utf8)!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a729439158766cfee5497c2b")!
        do {
            let result = try data.encrypt(algorithm: UInt32(kCCAlgorithmAES), key: key)
            let expected = Data(hexEncodedString: "0cb774fc5a0a3d4fbb9a6b582cb56b84")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed encrypting data with error: \(error)")
        }
    }
    
    func testDecryptAES() throws {
        let data = Data(hexEncodedString: "0cb774fc5a0a3d4fbb9a6b582cb56b84fa4e95678dbb6cc763bb4ce68df9155ffa4e95678dbb6cc763bb4ce68df9155ffa4e95678dbb6cc763bb4ce68df9155f")!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a729439158766cfee5497c2b")!
        do {
            let result = try data.decrypt(algorithm: UInt32(kCCAlgorithmAES), key: key)
            let decrypted = String(data: result, encoding: .utf8)!
            let expected = "Hello World!0000000000000000000000000000000000000000000000000000"
            XCTAssertEqual(decrypted, expected, "Got \(decrypted), expected: \(expected)")
        } catch {
            XCTFail("Failed decrypting data with error: \(error)")
        }
    }
    
    func testEncrypt3DES() throws {
        let data = "Hello World!0000".data(using: .utf8)!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a7294391")!
        do {
            let result = try data.encrypt(algorithm: UInt32(kCCAlgorithm3DES), key: key)
            let expected = Data(hexEncodedString: "b2b1619cecc9e1b2fba580d764af2c43")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed encrypting data with error: \(error)")
        }
    }
    
    func testDecrypt3DES() throws {
        let data = Data(hexEncodedString: "b2b1619cecc9e1b2fba580d764af2c43")!
        let key = Data(hexEncodedString: "5ec1bf26a34a6300c23bb45a9f8420495e472259a7294391")!
        do {
            let result = try data.decrypt(algorithm: UInt32(kCCAlgorithm3DES), key: key)
            let decrypted = String(data: result, encoding: .utf8)!
            let expected = "Hello World!0000"
            XCTAssertEqual(decrypted, expected, "Got \(decrypted), expected: \(expected)")
        } catch {
            XCTFail("Failed decrypting data with error: \(error)")
        }
    }
}
