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

extension RSA.PublicKey: DerRepresentable {
    // DER-encoded SubjectPublicKeyInfo (SPKI) for this RSA public key.
    public var der: Data {
        // rsaEncryption OID (1.2.840.113549.1.1.1) content bytes:
        // 06 09 2A 86 48 86 F7 0D 01 01 01
        let oidRSAEncryption = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        ).data

        let nullParams = TKBERTLVRecord(tag: 0x05, value: Data()).data

        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,  // SEQUENCE
            value: oidRSAEncryption + nullParams
        ).data

        // subjectPublicKey: BIT STRING with 0 unused bits + PKCS#1 RSAPublicKey DER
        var bitStringValue = Data([0x00])  // number of unused bits
        bitStringValue.append(pkcs1)
        let subjectPublicKey = TKBERTLVRecord(tag: 0x03, value: bitStringValue).data

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
        let spki = TKBERTLVRecord(tag: 0x30, value: algorithmIdentifier + subjectPublicKey).data
        return spki
    }
}
