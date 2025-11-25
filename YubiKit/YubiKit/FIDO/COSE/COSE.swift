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

/// COSE (CBOR Object Signing and Encryption) namespace.
///
/// Contains types and utilities for working with COSE structures
/// as defined in RFC 8152.
///
/// - SeeAlso: [RFC 8152: CBOR Object Signing and Encryption](https://www.rfc-editor.org/rfc/rfc8152.html)
/* public */ enum COSE {
    /// COSE algorithm identifier for FIDO2/WebAuthn.
    ///
    /// Supported algorithms for credential generation on YubiKey.
    /// Values from the IANA COSE Algorithms registry.
    ///
    /// - SeeAlso: [IANA COSE Algorithms Registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
    /* public */ enum Algorithm: Sendable, Equatable {
        /// ES256 algorithm (ECDSA with P-256 and SHA-256).
        case es256

        /// EdDSA algorithm (Ed25519).
        ///
        /// Supported on YubiKey firmware 5.2.X and above.
        case edDSA

        /// ES384 algorithm (ECDSA with P-384 and SHA-384).
        ///
        /// Supported on YubiKey firmware 5.6.X and above.
        case es384

        /// RS256 algorithm (RSASSA-PKCS1-v1_5 with SHA-256).
        ///
        /// Supported on YubiKey firmware 5.1.X and below only.
        case rs256

        /// Other algorithm not explicitly defined.
        ///
        /// Used for algorithms like ECDH-ES+HKDF-256 (-25) used in key agreement.
        case other(Int)

        /// The raw COSE algorithm identifier value.
        public var rawValue: Int {
            switch self {
            case .es256: return -7
            case .edDSA: return -8
            case .es384: return -35
            case .rs256: return -257
            case .other(let value): return value
            }
        }

        /// Initialize from a raw COSE algorithm identifier.
        ///
        /// - Parameter rawValue: COSE algorithm identifier from IANA registry
        public init(rawValue: Int) {
            switch rawValue {
            case -7: self = .es256
            case -8: self = .edDSA
            case -35: self = .es384
            case -257: self = .rs256
            default: self = .other(rawValue)
            }
        }
    }

    /// COSE Key representation with type-safe access to key parameters.
    ///
    /// Provides structured access to COSE key labels as defined in RFC 8152.
    /// The key type determines which parameters are available.
    ///
    /// - SeeAlso: [RFC 8152 Section 7: COSE Key Objects](https://www.rfc-editor.org/rfc/rfc8152.html#section-7)
    /* public */ enum Key: Sendable, Equatable {
        /// EC2 (Elliptic Curve) key with P-256 or P-384 curve.
        ///
        /// Used for ECDSA algorithms like ES256 (P-256) and ES384 (P-384).
        ///
        /// - Parameters:
        ///   - alg: Algorithm (COSE label 3: alg)
        ///   - kid: Optional key ID (COSE label 2: kid)
        ///   - crv: Curve identifier (COSE label -1: crv) - 1: P-256, 2: P-384
        ///   - x: X coordinate (COSE label -2: x)
        ///   - y: Y coordinate (COSE label -3: y)
        case ec2(alg: Algorithm, kid: Data?, crv: Int, x: Data, y: Data)

        /// OKP (Octet Key Pair) key for Ed25519 or X25519.
        ///
        /// Used for Ed25519 (EdDSA) and X25519 (ECDH) algorithms.
        ///
        /// - Parameters:
        ///   - alg: Algorithm (COSE label 3: alg)
        ///   - kid: Optional key ID (COSE label 2: kid)
        ///   - crv: Curve identifier (COSE label -1: crv) - 4: X25519, 5: X448, 6: Ed25519, 7: Ed448
        ///   - x: Public key bytes (COSE label -2: x)
        case okp(alg: Algorithm, kid: Data?, crv: Int, x: Data)

        /// RSA key.
        ///
        /// Used for RSA algorithms like RS256.
        ///
        /// - Parameters:
        ///   - alg: Algorithm (COSE label 3: alg)
        ///   - kid: Optional key ID (COSE label 2: kid)
        ///   - n: Modulus (COSE label -1: n)
        ///   - e: Public exponent (COSE label -2: e)
        case rsa(alg: Algorithm, kid: Data?, n: Data, e: Data)

        /// Unsupported or unknown key type.
        ///
        /// This case preserves unknown algorithms or key types for future compatibility.
        /// The associated value can only be created internally by YubiKit.
        case other(Unsupported)

        /// Unsupported COSE key type.
        ///
        /// Preserves the original CBOR structure for unknown algorithms or key types.
        /// Cannot be instantiated from outside YubiKit to prevent invalid data.
        /* public */ struct Unsupported: Sendable, Equatable {
            let cborData: Data

            internal init(cborData: Data) {
                self.cborData = cborData
            }
        }
    }
}

// MARK: - COSE.Key + CBOR

extension COSE.Key: CBOR.Decodable {
    /// Initialize a COSE Key from a CBOR value.
    ///
    /// Parses a COSE_Key structure from CBOR as defined in RFC 8152 Section 7.
    ///
    /// - Parameter cbor: CBOR map containing COSE key parameters
    /// - Returns: Parsed COSE.Key, or nil if parsing fails
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Label 1: kty (key type)
        guard let kty = map[.unsignedInt(1)]?.intValue else {
            return nil
        }

        // Label 3: alg (algorithm)
        guard let algValue = map[.unsignedInt(3)]?.intValue else {
            // Missing algorithm - store as .other
            self = .other(Unsupported(cborData: cbor.encode()))
            return
        }

        let alg = COSE.Algorithm(rawValue: algValue)

        // Label 2: kid (key ID, optional)
        let kid = map[.unsignedInt(2)]?.dataValue

        switch kty {
        case 2:  // EC2
            guard let crv = map[.negativeInt(0)]?.intValue,
                let x = map[.negativeInt(1)]?.dataValue,
                let y = map[.negativeInt(2)]?.dataValue
            else {
                return nil
            }
            self = .ec2(alg: alg, kid: kid, crv: crv, x: x, y: y)

        case 1:  // OKP
            guard let crv = map[.negativeInt(0)]?.intValue,
                let x = map[.negativeInt(1)]?.dataValue
            else {
                return nil
            }
            self = .okp(alg: alg, kid: kid, crv: crv, x: x)

        case 3:  // RSA
            guard let n = map[.negativeInt(0)]?.dataValue,
                let e = map[.negativeInt(1)]?.dataValue
            else {
                return nil
            }
            self = .rsa(alg: alg, kid: kid, n: n, e: e)

        default:
            // Unknown key type - store as .other
            self = .other(Unsupported(cborData: cbor.encode()))
        }
    }
}

extension COSE.Key: CBOR.Encodable {
    /// Encode the COSE Key to CBOR.
    ///
    /// Produces a COSE_Key structure as defined in RFC 8152 Section 7.
    ///
    /// - Returns: CBOR map value containing all COSE key parameters
    func cbor() -> CBOR.Value {
        switch self {
        case .ec2(let alg, let kid, let crv, let x, let y):
            var map: [CBOR.Value: CBOR.Value] = [
                .unsignedInt(1): .unsignedInt(2),  // Label 1: kty = EC2
                .unsignedInt(3): CBOR.Value(Int64(alg.rawValue)),  // Label 3: alg
                .negativeInt(0): CBOR.Value(Int64(crv)),  // Label -1: crv
                .negativeInt(1): .byteString(x),  // Label -2: x
                .negativeInt(2): .byteString(y),  // Label -3: y
            ]
            if let kid = kid {
                map[.unsignedInt(2)] = .byteString(kid)  // Label 2: kid
            }
            return .map(map)

        case .okp(let alg, let kid, let crv, let x):
            var map: [CBOR.Value: CBOR.Value] = [
                .unsignedInt(1): .unsignedInt(1),  // Label 1: kty = OKP
                .unsignedInt(3): CBOR.Value(Int64(alg.rawValue)),  // Label 3: alg
                .negativeInt(0): CBOR.Value(Int64(crv)),  // Label -1: crv
                .negativeInt(1): .byteString(x),  // Label -2: x
            ]
            if let kid = kid {
                map[.unsignedInt(2)] = .byteString(kid)  // Label 2: kid
            }
            return .map(map)

        case .rsa(let alg, let kid, let n, let e):
            var map: [CBOR.Value: CBOR.Value] = [
                .unsignedInt(1): .unsignedInt(3),  // Label 1: kty = RSA
                .unsignedInt(3): CBOR.Value(Int64(alg.rawValue)),  // Label 3: alg
                .negativeInt(0): .byteString(n),  // Label -1: n
                .negativeInt(1): .byteString(e),  // Label -2: e
            ]
            if let kid = kid {
                map[.unsignedInt(2)] = .byteString(kid)  // Label 2: kid
            }
            return .map(map)

        case .other(let unsupported):
            // Re-decode the stored COSE key data.
            // This must succeed because we validated it during init.
            return try! unsupported.cborData.decode()!
        }
    }
}
