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
    func publicKey(from yubiKeyData: Data, type: PIV.KeyType) throws -> PublicKey {
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: yubiKeyData) else {
            throw PIV.SessionError.dataParseError
        }

        switch type {
        case let .ecc(curve):
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw PIV.SessionError.invalidResponse
            }

            guard let key = EC.PublicKey(uncompressedPoint: keyData),
                key.curve == curve
            else {
                throw PIV.SessionError.dataParseError
            }

            return .ec(key)

        case let .rsa(keySize):
            guard let modulus = records.recordWithTag(0x81)?.value,
                let exponent = records.recordWithTag(0x82)?.value
            else {
                throw PIV.SessionError.invalidResponse
            }

            guard let key = RSA.PublicKey(n: modulus, e: exponent), key.size == keySize else {
                throw PIV.SessionError.invalidKeyLength
            }

            return .rsa(key)

        case .ed25519:
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw PIV.SessionError.invalidResponse
            }

            guard let key = Ed25519.PublicKey(keyData: keyData) else {
                throw PIV.SessionError.dataParseError
            }

            return .ed25519(key)

        case .x25519:
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw PIV.SessionError.invalidResponse
            }

            guard let key = X25519.PublicKey(keyData: keyData) else {
                throw PIV.SessionError.dataParseError
            }

            return .x25519(key)
        }
    }
}
