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
import CryptoKit
import Foundation
import Testing

@testable import YubiKit

struct PIVDataFormatterTests {

    // Test data for ECDSA signing with messages
    struct ECDSATestCase: Sendable {
        let curve: EC.Curve
        let algorithm: PIV.ECDSASignatureAlgorithm
        let expectedHex: String
    }

    @Test(
        "Prepare ECDSA Signing",
        arguments: [
            ECDSATestCase(
                curve: .secp256r1,
                algorithm: .hash(.sha256),
                expectedHex: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
            ),
            ECDSATestCase(
                curve: .secp384r1,
                algorithm: .hash(.sha256),
                expectedHex:
                    "00000000000000000000000000000000c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
            ),
            ECDSATestCase(
                curve: .secp256r1,
                algorithm: .hash(.sha1),
                expectedHex: "000000000000000000000000d3486ae9136e7856bc42212385ea797094475802"
            ),
            ECDSATestCase(
                curve: .secp256r1,
                algorithm: .hash(.sha512),
                expectedHex: "f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad"
            ),
            ECDSATestCase(
                curve: .secp384r1,
                algorithm: .hash(.sha512),
                expectedHex:
                    "f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad6094f517a2182360c9aacf6a3dc32316"
            ),
        ]
    )
    func prepareECDSASigning(testCase: ECDSATestCase) throws {
        let data = "Hello world!".data(using: .utf8)!
        let result = PIVDataFormatter.prepareDataForECDSASigning(
            data,
            curve: testCase.curve,
            algorithm: testCase.algorithm
        )
        let expected = Data(hexEncodedString: testCase.expectedHex)!
        #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
    }

    @Test func prepareECDSADigestSigning() throws {
        let data = Data(hexEncodedString: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
        do {
            let result = PIVDataFormatter.prepareDataForECDSASigning(
                data,
                curve: .secp256r1,
                algorithm: .prehashed(.sha256)
            )
            let expected = Data(hexEncodedString: "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")!
            #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        }
    }

    // Test data for RSA signing
    struct RSATestCase {
        let algorithm: PIV.RSASignatureAlgorithm
        let expectedHex: String
    }

    @Test(
        "Prepare RSA Signing",
        arguments: [
            RSATestCase(
                algorithm: .pkcs1v15(.sha256),
                expectedHex:
                    "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
            ),
            RSATestCase(
                algorithm: .pkcs1v15(.sha1),
                expectedHex:
                    "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414d3486ae9136e7856bc42212385ea797094475802"
            ),
        ]
    )
    func prepareRSASigning(testCase: RSATestCase) throws {
        let data = "Hello world!".data(using: .utf8)!
        let result = try PIVDataFormatter.prepareDataForRSASigning(
            data,
            keySize: .bits1024,
            algorithm: testCase.algorithm
        )
        let expected = Data(hexEncodedString: testCase.expectedHex)!
        #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
    }

    @Test func prepareECDSADigestSigningP384WithPadding() throws {
        let data = "Hello world!".data(using: .utf8)!
        do {
            let result = PIVDataFormatter.prepareDataForECDSASigning(
                data,
                curve: .secp384r1,
                algorithm: .prehashed(.sha256)
            )
            let expected = Data(
                hexEncodedString:
                    "00000000000000000000000000000000000000000000000000000000000000000000000048656c6c6f20776f726c6421"
            )!
            #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
        }
    }

    // Test data for RSA decryption
    struct RSADecryptionTestCase {
        let algorithm: PIV.RSAEncryptionAlgorithm
        let encryptedHex: String
    }

    @Test(
        "Extract RSA Encryption",
        arguments: [
            RSADecryptionTestCase(
                algorithm: .pkcs1v15,
                encryptedHex:
                    "00022b781255b78f9570844701748107f506effbea5f0822b41dded192938906cefe16eef190d4cf7f7b0866badf94ca0e4e08fda43e4619edec2703987a56a78aa4c2d36a8f89c43f1f9c0ab681e45a759744ef946d65d95e74536b28b83cdc1c62e36c014c8b4a50c178a54306ce7395240e0048656c6c6f20576f726c6421"
            ),
            RSADecryptionTestCase(
                algorithm: .oaep(.sha224),
                encryptedHex:
                    "00bcbb35b6ef5c94a85fb3439a6dabda617a08963cf81023bac19c619b024cb71b8aee25cc30991279c908198ba623fba88547741dbf17a6f2a737ec95542b56b2b429bea8bd3145af7c8f144dcf804b89d3f9de21d6d6dc852fc91c666b8582bf348e1388ac2f54651ae6a1f5355c8d96daf96c922a9f1a499d890412d09454"
            ),
        ]
    )
    func extractRSAEncryption(testCase: RSADecryptionTestCase) throws {
        let data = Data(hexEncodedString: testCase.encryptedHex)!
        let result = try PIVDataFormatter.extractDataFromRSAEncryption(data, algorithm: testCase.algorithm)
        let expected = "Hello World!".data(using: .utf8)!
        #expect(result == expected, "Got \(result.hexEncodedString), expected: \(expected.hexEncodedString)")
    }

    @Test func extractMalformedRSAData() throws {
        let data = Data(
            hexEncodedString:
                "79ce573cfc2bdfe835175ffd4bd01ab35eccfd31e2b009a1943123e9cb2db4878608c821fb96a6c63382aaf1c12ce0f03b83"
        )!
        do {
            let _ = try PIVDataFormatter.extractDataFromRSAEncryption(data, algorithm: .pkcs1v15)
            Issue.record("extractDataFromRSAEncryption returned although the data had the wrong size.")
        } catch PIV.SessionError.invalidDataSize {
            #expect(true, "Failed as expected with invalid data size error")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}
