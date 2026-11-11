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

#if compiler(>=6.2)
@available(iOS 26, macOS 26, *)
extension Crypto.MLDSA {
    static func isValidSignature(_ signature: Data, for message: Data, key: MLDSA.PublicKey) throws -> Bool {
        switch key.parameterSet {
        case .mlDSA44:
            throw CryptoError.unsupportedAlgorithm
        case .mlDSA65:
            let publicKey = try CryptoKit.MLDSA65.PublicKey(rawRepresentation: key.keyData)
            return publicKey.isValidSignature(signature, for: message)
        case .mlDSA87:
            let publicKey = try CryptoKit.MLDSA87.PublicKey(rawRepresentation: key.keyData)
            return publicKey.isValidSignature(signature, for: message)
        }
    }
}

@available(iOS 26, macOS 26, *)
extension Crypto.MLKEM {
    static func encapsulate(key: MLKEM.PublicKey) throws -> MLKEM.Encapsulation {
        switch key.parameterSet {
        case .mlKEM512:
            throw CryptoError.unsupportedAlgorithm
        case .mlKEM768:
            let publicKey = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: key.keyData)
            let result = try publicKey.encapsulate()
            return MLKEM.Encapsulation(
                ciphertext: result.encapsulated,
                sharedSecret: result.sharedSecret.withUnsafeBytes { Data($0) }
            )
        case .mlKEM1024:
            let publicKey = try CryptoKit.MLKEM1024.PublicKey(rawRepresentation: key.keyData)
            let result = try publicKey.encapsulate()
            return MLKEM.Encapsulation(
                ciphertext: result.encapsulated,
                sharedSecret: result.sharedSecret.withUnsafeBytes { Data($0) }
            )
        }
    }
}
#endif
