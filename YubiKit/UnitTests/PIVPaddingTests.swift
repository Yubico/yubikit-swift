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
import CryptoKit

final class PIVPaddingTests: XCTestCase {

    func testPadSHA256ECCP256() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA256)
            let expected = Data(hexEncodedString: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA256ECCP384() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP384, algorithm: .ecdsaSignatureMessageX962SHA256)
            let expected = Data(hexEncodedString: "00000000000000000000000000000000c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA1ECCP256() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA1)
            let expected = Data(hexEncodedString: "000000000000000000000000d3486ae9136e7856bc42212385ea797094475802")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA512ECCP256() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA512)
            let expected = Data(hexEncodedString: "f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }

    func testPadSHA512ECCP384() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP384, algorithm: .ecdsaSignatureMessageX962SHA512)
            let expected = Data(hexEncodedString: "f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad6094f517a2182360c9aacf6a3dc32316")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPreHashedECCP256() throws {
        let data = Data(hexEncodedString: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP256, algorithm: .ecdsaSignatureDigestX962SHA256)
            let expected = Data(hexEncodedString: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA256WithRSA() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .RSA1024, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
            let expected = Data(hexEncodedString: "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA1WithRSA() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .RSA1024, algorithm: .rsaSignatureMessagePKCS1v15SHA1)
            let expected = Data(hexEncodedString: "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414d3486ae9136e7856bc42212385ea797094475802")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testPadSHA256ECCP384Digest() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = try PIVPadding.padData(data, keyType: .ECCP384, algorithm: .ecdsaSignatureDigestX962SHA256)
            let expected = Data(hexEncodedString: "00000000000000000000000000000000000000000000000000000000000000000000000048656c6c6f20776f726c6421")!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testUnpadRSAEncryptionPKCS1Padded() throws {
        let data = Data(hexEncodedString: "00022b781255b78f9570844701748107f506effbea5f0822b41dded192938906cefe16eef190d4cf7f7b0866badf94ca0e4e08fda43e4619edec2703987a56a78aa4c2d36a8f89c43f1f9c0ab681e45a759744ef946d65d95e74536b28b83cdc1c62e36c014c8b4a50c178a54306ce7395240e0048656c6c6f20576f726c6421")!
        do {
            let result = try PIVPadding.unpadRSAData(data, algorithm: .rsaEncryptionPKCS1)
            let expected = "Hello World!".data(using: .utf8)!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testUnpadRSAEncryptionOAEPSHA224() throws {
        let data = Data(hexEncodedString: "00bcbb35b6ef5c94a85fb3439a6dabda617a08963cf81023bac19c619b024cb71b8aee25cc30991279c908198ba623fba88547741dbf17a6f2a737ec95542b56b2b429bea8bd3145af7c8f144dcf804b89d3f9de21d6d6dc852fc91c666b8582bf348e1388ac2f54651ae6a1f5355c8d96daf96c922a9f1a499d890412d09454")!
        do {
            let result = try PIVPadding.unpadRSAData(data, algorithm: .rsaEncryptionOAEPSHA224)
            let expected = "Hello World!".data(using: .utf8)!
            XCTAssertEqual(result, expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        } catch {
            XCTFail("Failed padding data with error: \(error)")
        }
    }
    
    func testUnpadMalformedData() throws {
        let data = Data(hexEncodedString: "00bcbb35b6ef5c94a85fb3439a6dabda617a08963cf81023bac19c619b024cb71b8aee25cc30991279c908198ba623fba88547741dbf17a6f2a737ec95542b56b2b429bea8bd3145af7c8f144dcf804b89d3f9de21d6d6dc852fc91c666b8582bf348e1388ac2f54651ae6a1f5355c8d96daf96c922a9f1a499d890412d09454")!
        do {
            let _ = try PIVPadding.unpadRSAData(data, algorithm: .rsaEncryptionPKCS1)
            XCTFail("unpadRSAData returned although the data had the wrong size.")
        } catch {
            XCTAssert(true, "Failed as expeced with: \(error)")
        }
    }
}
