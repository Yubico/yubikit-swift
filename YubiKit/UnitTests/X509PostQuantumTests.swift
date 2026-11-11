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
        let url = try #require(Bundle.module.url(forResource: "ml-dsa44", withExtension: "der"))
        let certificate = X509Cert(der: try Data(contentsOf: url))
        let key = try #require(certificate.publicKey)
        guard case .mlDSA(let mlDSAKey) = key else {
            Issue.record("Expected ML-DSA public key")
            return
        }
        #expect(mlDSAKey.parameterSet == .mlDSA44)
        #expect(mlDSAKey.keyData.count == 1312)
    }

    @Test func rejectsTruncatedCertificate() throws {
        let url = try #require(Bundle.module.url(forResource: "ml-dsa44", withExtension: "der"))
        let der = try Data(contentsOf: url)
        #expect(X509Cert(der: Data(der.dropLast())).publicKey == nil)
    }

    #if compiler(>=6.2)
    @Test func verifiesMLDSASignatureWithCryptoKit() throws {
        guard #available(macOS 26, iOS 26, *) else { return }
        let privateKey = try CryptoKit.MLDSA65.PrivateKey()
        let key = try #require(MLDSA.PublicKey(keyData: privateKey.publicKey.rawRepresentation, parameterSet: .mlDSA65))
        let message = Data("test message".utf8)
        let signature = try privateKey.signature(for: message)
        #expect(try key.isValidSignature(signature, for: message))
        #expect(try !key.isValidSignature(signature, for: Data("other".utf8)))
    }

    @Test func encapsulatesWithCryptoKit() throws {
        guard #available(macOS 26, iOS 26, *) else { return }
        let privateKey = try CryptoKit.MLKEM768.PrivateKey()
        let key = try #require(
            MLKEM.PublicKey(keyData: privateKey.publicKey.rawRepresentation, parameterSet: .mlKEM768)
        )
        let result = try key.encapsulate()
        let sharedSecret = try privateKey.decapsulate(result.ciphertext)
        #expect(result.ciphertext.count == MLKEM.ParameterSet.mlKEM768.ciphertextByteCount)
        #expect(result.sharedSecret == sharedSecret.withUnsafeBytes { Data($0) })
    }

    @Test func reportsUnsupportedCryptoKitParameterSets() throws {
        guard #available(macOS 26, iOS 26, *) else { return }
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
