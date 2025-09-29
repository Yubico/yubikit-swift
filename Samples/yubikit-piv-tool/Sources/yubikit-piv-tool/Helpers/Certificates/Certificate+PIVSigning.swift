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
import PotentASN1
import Shield
import YubiKit

// MARK: - Shield Certificate.Builder Extension for external signing with YubiKey

extension ShieldX509.Certificate.Builder {
    public func buildWithPIV(
        slot: PIV.Slot,
        session: PIVSession,
        keyType: PIV.KeyType,
        algorithm: PIV.HashAlgorithm
    ) async throws -> ShieldX509.Certificate? {
        guard let signatureAlgorithm = try AlgorithmIdentifier(algorithm: algorithm, keyType: keyType)
        else {  // Unsupported combination
            return nil
        }

        // Build the TBS certificate
        let tbsCertificate = try buildInfo(signatureAlgorithm: signatureAlgorithm)

        // Encode TBS to DER
        let tbsData = try Data(tbsCertificate.encoded())

        // Sign with PIV hardware
        let signature: Data!
        switch keyType {
        case let .rsa(keySize):
            do {
                signature = try await session.sign(
                    tbsData,
                    in: slot,
                    keyType: .rsa(keySize),
                    using: .pkcs1v15(algorithm)
                )
            } catch {
                handlePIVError(error)
            }
        case let .ecc(curve):
            do {
                signature = try await session.sign(
                    tbsData,
                    in: slot,
                    keyType: .ecc(curve),
                    using: .digest(algorithm)
                )
            } catch {
                handlePIVError(error)
            }
        case .x25519, .ed25519:
            return nil
        }

        // Create the final certificate
        return ShieldX509.Certificate(
            tbsCertificate: tbsCertificate,
            signatureAlgorithm: signatureAlgorithm,
            signature: BitString(bytes: signature)
        )
    }
}
