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

extension CTAP2.MakeCredential.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: fmt (0x01) - attestation format
        guard let format: String = map[.int(0x01)]?.cborDecoded() else {
            return nil
        }

        // Required: authData (0x02) - authenticator data
        guard let authDataBytes: Data = map[.int(0x02)]?.cborDecoded(),
            let authData = WebAuthn.AuthenticatorData(data: authDataBytes)
        else {
            return nil
        }

        // Required: attStmt (0x03) - attestation statement
        guard let statementCBOR = map[.int(0x03)] else {
            return nil
        }

        // Build attestation object from components
        self.attestationObject = WebAuthn.AttestationObject(
            format: format,
            statementCBOR: statementCBOR,
            authenticatorData: authData
        )

        // Optional: epAtt (0x04) - enterprise attestation
        self.enterpriseAttestation = map[.int(0x04)]?.cborDecoded()

        // Optional: largeBlobKey (0x05)
        self.largeBlobKey = map[.int(0x05)]?.cborDecoded()

        // Optional: unsignedExtensionOutputs (0x06)
        if let extMap = map[.int(0x06)]?.mapValue {
            var unsignedOutputs: [String: CBOR.Value] = [:]
            for (key, value) in extMap {
                guard let name = key.stringValue else {
                    return nil  // Extension keys must be strings
                }
                unsignedOutputs[name] = value
            }
            self.unsignedExtensionOutputs = unsignedOutputs
        } else {
            self.unsignedExtensionOutputs = nil
        }
    }
}
