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
    func publicKey(from yubiKeyData: Data, type: PIV.KeyType) throws(PIVSessionError) -> PublicKey {
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: yubiKeyData) else {
            throw .dataProcessingError("Failed to create public key from data", source: .here())
        }

        switch type {
        case let .ec(curve):
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw .responseParseError("Missing EC key data in TLV record", source: .here())
            }

            guard let key = EC.PublicKey(x963Representation: keyData, curve: curve),
                key.curve == curve
            else {
                throw .dataProcessingError("Failed to create public key from data", source: .here())
            }

            return .ec(key)

        case let .rsa(keySize):
            guard let modulus = records.recordWithTag(0x81)?.value,
                let exponent = records.recordWithTag(0x82)?.value
            else {
                throw .responseParseError("Missing RSA modulus or exponent in TLV records", source: .here())
            }

            guard let key = RSA.PublicKey(n: modulus, e: exponent), key.size == keySize else {
                throw .invalidKeyLength(source: .here())
            }

            return .rsa(key)

        case .ed25519:
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw .responseParseError("Missing Ed25519 key data in TLV record", source: .here())
            }

            guard let key = Ed25519.PublicKey(keyData: keyData) else {
                throw .dataProcessingError("Failed to create public key from data", source: .here())
            }

            return .ed25519(key)

        case .x25519:
            guard let keyData = records.recordWithTag(0x86)?.value else {
                throw .responseParseError("Missing X25519 key data in TLV record", source: .here())
            }

            guard let key = X25519.PublicKey(keyData: keyData) else {
                throw .dataProcessingError("Failed to create public key from data", source: .here())
            }

            return .x25519(key)
        }
    }
}
