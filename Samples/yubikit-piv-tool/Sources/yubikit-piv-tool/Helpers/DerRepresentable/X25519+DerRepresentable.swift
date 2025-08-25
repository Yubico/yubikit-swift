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

extension X25519.PublicKey: DerRepresentable {
    // DER-encoded SubjectPublicKeyInfo (SPKI) for this X25519 public key.
    public var der: Data {
        // X25519 OID (1.3.101.110):
        // 06 03 2B 65 6E
        let oidX25519 = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2B, 0x65, 0x6E])
        ).data

        // Algorithm identifier: SEQUENCE { X25519 OID }
        // No parameters for X25519
        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,  // SEQUENCE
            value: oidX25519
        ).data

        // subjectPublicKey: BIT STRING with 0 unused bits + raw key data
        var bitStringValue = Data([0x00])  // number of unused bits
        bitStringValue.append(keyData)
        let subjectPublicKey = TKBERTLVRecord(tag: 0x03, value: bitStringValue).data

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
        let spki = TKBERTLVRecord(tag: 0x30, value: algorithmIdentifier + subjectPublicKey).data
        return spki
    }
}
