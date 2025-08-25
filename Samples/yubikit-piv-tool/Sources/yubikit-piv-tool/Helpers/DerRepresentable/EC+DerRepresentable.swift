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
import YubiKit

extension EC.PublicKey: DerRepresentable {
    // DER-encoded SubjectPublicKeyInfo (SPKI) for this EC public key.
    public var der: Data {
        // Determine the curve OID based on the key's curve
        let curveOID: Data
        switch curve {
        case .p256:
            // secp256r1/prime256v1 OID (1.2.840.10045.3.1.7):
            // 06 08 2A 86 48 CE 3D 03 01 07
            curveOID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        case .p384:
            // secp384r1 OID (1.3.132.0.34):
            // 06 05 2B 81 04 00 22
            curveOID = Data([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22])
        }

        // ecPublicKey OID (1.2.840.10045.2.1):
        // 06 07 2A 86 48 CE 3D 02 01
        let oidECPublicKey = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        ).data

        // Algorithm identifier: SEQUENCE { ecPublicKey OID, curve OID }
        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,  // SEQUENCE
            value: oidECPublicKey + curveOID
        ).data

        // subjectPublicKey: BIT STRING with 0 unused bits + uncompressed point
        var bitStringValue = Data([0x00])  // number of unused bits
        bitStringValue.append(uncompressedPoint)
        let subjectPublicKey = TKBERTLVRecord(tag: 0x03, value: bitStringValue).data

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
        let spki = TKBERTLVRecord(tag: 0x30, value: algorithmIdentifier + subjectPublicKey).data
        return spki
    }
}
