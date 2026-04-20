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

// MARK: - SubjectPublicKeyInfo (SPKI) DER Encoding
//
// Encodes public keys as DER-encoded SubjectPublicKeyInfo per RFC 5280:
//
//   SubjectPublicKeyInfo ::= SEQUENCE {
//       algorithm  AlgorithmIdentifier,
//       subjectPublicKey  BIT STRING
//   }

extension PublicKey {
    /// DER-encoded SubjectPublicKeyInfo (SPKI) representation of this public key.
    public var spki: Data {
        switch self {
        case .ec(let key): key.spki
        case .rsa(let key): key.spki
        case .ed25519(let key): key.spki
        case .x25519(let key): key.spki
        }
    }
}

// MARK: - EC

extension EC.PublicKey {
    /// DER-encoded SubjectPublicKeyInfo (SPKI) for this EC public key.
    public var spki: Data {
        let curveOID: Data
        switch curve {
        case .secp256r1:
            // secp256r1/prime256v1 OID (1.2.840.10045.3.1.7)
            curveOID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        case .secp384r1:
            // secp384r1 OID (1.3.132.0.34)
            curveOID = Data([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22])
        }

        // ecPublicKey OID (1.2.840.10045.2.1)
        let oidECPublicKey = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        ).data

        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,
            value: oidECPublicKey + curveOID
        ).data

        return makeSPKI(algorithmIdentifier: algorithmIdentifier, rawKey: x963)
    }
}

// MARK: - RSA

extension RSA.PublicKey {
    /// DER-encoded SubjectPublicKeyInfo (SPKI) for this RSA public key.
    ///
    /// This is the SPKI wrapping (`AlgorithmIdentifier` + BIT STRING of PKCS #1
    /// `RSAPublicKey`). For the bare `SEQUENCE { n, e }` encoding, use ``pkcs1``.
    public var spki: Data {
        // rsaEncryption OID (1.2.840.113549.1.1.1)
        let oidRSAEncryption = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        ).data

        let nullParams = TKBERTLVRecord(tag: 0x05, value: Data()).data

        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,
            value: oidRSAEncryption + nullParams
        ).data

        return makeSPKI(algorithmIdentifier: algorithmIdentifier, rawKey: pkcs1)
    }
}

// MARK: - Ed25519

extension Ed25519.PublicKey {
    /// DER-encoded SubjectPublicKeyInfo (SPKI) for this Ed25519 public key.
    public var spki: Data {
        // Ed25519 OID (1.3.101.112)
        let oidEd25519 = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2B, 0x65, 0x70])
        ).data

        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,
            value: oidEd25519
        ).data

        return makeSPKI(algorithmIdentifier: algorithmIdentifier, rawKey: keyData)
    }
}

// MARK: - X25519

extension X25519.PublicKey {
    /// DER-encoded SubjectPublicKeyInfo (SPKI) for this X25519 public key.
    public var spki: Data {
        // X25519 OID (1.3.101.110)
        let oidX25519 = TKBERTLVRecord(
            tag: 0x06,
            value: Data([0x2B, 0x65, 0x6E])
        ).data

        let algorithmIdentifier = TKBERTLVRecord(
            tag: 0x30,
            value: oidX25519
        ).data

        return makeSPKI(algorithmIdentifier: algorithmIdentifier, rawKey: keyData)
    }
}

// MARK: - DER Helpers

private func makeSPKI(algorithmIdentifier: Data, rawKey: Data) -> Data {
    var bitStringValue = Data([0x00])
    bitStringValue.append(rawKey)
    let subjectPublicKey = TKBERTLVRecord(tag: 0x03, value: bitStringValue).data
    return TKBERTLVRecord(tag: 0x30, value: algorithmIdentifier + subjectPublicKey).data
}
