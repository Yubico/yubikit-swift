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

import CryptoTokenKit
import Foundation

extension PIVSession {
    func publicKey(from yubiKeyData: Data, type: PIVKeyType) throws -> PublicKey {
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: yubiKeyData) else {
            throw PIVSessionError.dataParseError
        }

        switch type {
        case let .ecc(curve):
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw PIVSessionError.invalidResponse
            }

            guard let key = EC.PublicKey(uncompressedPoint: keyData),
                key.curve == curve
            else {
                throw PIVSessionError.dataParseError
            }

            return .ec(key)

        case let .rsa(keySize):
            guard let modulus = records.recordWithTag(0x81)?.value,
                let exponent = records.recordWithTag(0x82)?.value
            else {
                throw PIVSessionError.invalidResponse
            }

            guard let key = RSA.PublicKey(n: modulus, e: exponent), key.size == keySize else {
                throw PIVSessionError.badKeyLength
            }

            return .rsa(key)
        }
    }
}
