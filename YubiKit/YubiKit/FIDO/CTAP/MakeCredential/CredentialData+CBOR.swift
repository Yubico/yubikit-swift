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
    /// CBOR map keys for makeCredential response
    private enum ResponseKey: UInt64 {
        case fmt = 0x01
        case authData = 0x02
        case attStmt = 0x03
        case epAtt = 0x04
        case largeBlobKey = 0x05
        case unsignedExtensionOutputs = 0x06
    }

    init?(cbor: CBOR.Value) {
        guard let responseMap = cbor.mapValue else {
            return nil
        }

        // Required: fmt (attestation format)
        guard let fmt = responseMap[.unsignedInt(ResponseKey.fmt.rawValue)]?.stringValue else {
            return nil
        }
        self.format = fmt

        // Required: authData (authenticator data)
        guard let authDataBytes = responseMap[.unsignedInt(ResponseKey.authData.rawValue)]?.dataValue,
            let authData = AuthenticatorData(data: authDataBytes)
        else {
            return nil
        }
        self.authenticatorData = authData

        // Required: attStmt (attestation statement)
        guard let attStmtValue = responseMap[.unsignedInt(ResponseKey.attStmt.rawValue)] else {
            return nil
        }
        self.attestationStatement = AttestationStatement(format: fmt, statement: attStmtValue)

        // Optional: epAtt (enterprise attestation)
        self.enterpriseAttestation = responseMap[.unsignedInt(ResponseKey.epAtt.rawValue)]?.boolValue

        // Optional: largeBlobKey
        self.largeBlobKey = responseMap[.unsignedInt(ResponseKey.largeBlobKey.rawValue)]?.dataValue

        // Optional: unsignedExtensionOutputs
        if let unsignedExtValue = responseMap[.unsignedInt(ResponseKey.unsignedExtensionOutputs.rawValue)] {
            self.unsignedExtensionOutputs = ExtensionOutputs(cbor: unsignedExtValue)
        } else {
            self.unsignedExtensionOutputs = nil
        }
    }
}
