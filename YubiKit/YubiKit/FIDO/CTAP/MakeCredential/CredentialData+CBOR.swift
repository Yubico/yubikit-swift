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

import Foundation

// MARK: - CredentialData + CBOR

extension CredentialData: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: fmt (0x01) - attestation format
        guard let fmt: String = map[.unsignedInt(0x01)]?.cborDecoded() else {
            return nil
        }
        self.format = fmt

        // Required: authData (0x02) - authenticator data
        guard let authDataBytes: Data = map[.unsignedInt(0x02)]?.cborDecoded(),
            let authData = AuthenticatorData(data: authDataBytes)
        else {
            return nil
        }
        self.authenticatorData = authData

        // Required: attStmt (0x03) - attestation statement
        guard let attStmtValue = map[.unsignedInt(0x03)] else {
            return nil
        }

        // Decode based on format
        let attStmt: AttestationStatement
        switch fmt {
        case "packed":
            guard let packed = PackedAttestation(cbor: attStmtValue) else {
                return nil  // Known format but invalid CBOR structure
            }
            attStmt = .packed(packed)
        case "fido-u2f":
            guard let fidoU2F = FIDOU2FAttestation(cbor: attStmtValue) else {
                return nil  // Known format but invalid CBOR structure
            }
            attStmt = .fidoU2F(fidoU2F)
        case "none":
            attStmt = .none
        case "apple":
            guard let apple = AppleAttestation(cbor: attStmtValue) else {
                return nil  // Known format but invalid CBOR structure
            }
            attStmt = .apple(apple)
        default:
            // Unknown format - preserve for future compatibility
            attStmt = .unknown(format: fmt)
        }
        self.attestationStatement = attStmt

        // Optional: epAtt (0x04) - enterprise attestation
        self.enterpriseAttestation = map[.unsignedInt(0x04)]?.cborDecoded()

        // Optional: largeBlobKey (0x05)
        self.largeBlobKey = map[.unsignedInt(0x05)]?.cborDecoded()

        // Optional: unsignedExtensionOutputs (0x06)
        self.unsignedExtensionOutputs = map[.unsignedInt(0x06)]?.cborDecoded()
    }
}
