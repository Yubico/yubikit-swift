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

struct X509PostQuantumTests {
    @Test func extractsMLDSAPublicKey() throws {
        let certificate = X509Cert(der: try #require(testCertificateDER))
        let key = try #require(certificate.publicKey)
        guard case .mlDSA(let mlDSAKey) = key else {
            Issue.record("Expected ML-DSA public key")
            return
        }
        #expect(mlDSAKey.parameterSet == .mlDSA44)
        #expect(mlDSAKey.keyData.count == 1312)
    }

    @Test func rejectsTruncatedCertificate() throws {
        let der = try #require(testCertificateDER)
        #expect(X509Cert(der: Data(der.dropLast())).publicKey == nil)
    }

    @Test func extractsPublicKeyFromDataSlice() throws {
        let der = try #require(testCertificateDER)
        let prefixed = Data([0, 1, 2]) + der
        let slice = prefixed[3...]
        #expect(slice.startIndex == 3)
        guard case .mlDSA(let key) = X509Cert(der: slice).publicKey else {
            Issue.record("Expected ML-DSA public key")
            return
        }
        #expect(key.parameterSet == .mlDSA44)
    }

    #if compiler(>=6.2)
    @available(iOS 26, macOS 26, *)
    @Test func verifiesMLDSASignatureWithCryptoKit() throws {
        let privateKey = try CryptoKit.MLDSA65.PrivateKey()
        let key = try #require(MLDSA.PublicKey(keyData: privateKey.publicKey.rawRepresentation, parameterSet: .mlDSA65))
        let message = Data("test message".utf8)
        let context = Data("PIV".utf8)
        let signature = try privateKey.signature(for: message, context: context)
        #expect(try key.isValidSignature(signature, for: message, context: context))
        #expect(try !key.isValidSignature(signature, for: message))
        #expect(try !key.isValidSignature(signature, for: Data("other".utf8), context: context))
    }

    @available(iOS 26, macOS 26, *)
    @Test func encapsulatesWithCryptoKit() throws {
        let privateKey = try CryptoKit.MLKEM768.PrivateKey()
        let key = try #require(
            MLKEM.PublicKey(keyData: privateKey.publicKey.rawRepresentation, parameterSet: .mlKEM768)
        )
        let result = try key.encapsulate()
        let sharedSecret = try privateKey.decapsulate(result.ciphertext)
        #expect(result.ciphertext.count == MLKEM.ParameterSet.mlKEM768.ciphertextByteCount)
        #expect(result.sharedSecret == sharedSecret.withUnsafeBytes { Data($0) })
    }

    @available(iOS 26, macOS 26, *)
    @Test func reportsUnsupportedCryptoKitParameterSets() throws {
        let mlDSA44 = try #require(MLDSA.PublicKey(keyData: Data(count: 1312), parameterSet: .mlDSA44))
        let mlKEM512 = try #require(MLKEM.PublicKey(keyData: Data(count: 800), parameterSet: .mlKEM512))
        #expect(throws: CryptoError.self) {
            try mlDSA44.isValidSignature(Data(), for: Data())
        }
        #expect(throws: CryptoError.self) {
            try mlKEM512.encapsulate()
        }
    }
    #endif
}

private let testCertificateDER = Data(
    base64Encoded: """
        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
        """,
    options: .ignoreUnknownCharacters
)
