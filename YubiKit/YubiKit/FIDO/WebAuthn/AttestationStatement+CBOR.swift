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

// MARK: - AttestationStatement + CBOR

extension AttestationStatement {
    /// Initialize from CBOR format identifier and attestation statement map.
    ///
    /// - Parameters:
    ///   - format: The attestation format identifier string.
    ///   - statement: The attestation statement CBOR value.
    init(format: String, statement: CBOR.Value) {
        switch format {
        case "packed":
            if let packed = PackedAttestation(cbor: statement) {
                self = .packed(packed)
            } else {
                self = .other(format: format, statement: statement)
            }
        case "fido-u2f":
            if let fidoU2F = FIDOU2FAttestation(cbor: statement) {
                self = .fidoU2F(fidoU2F)
            } else {
                self = .other(format: format, statement: statement)
            }
        case "none":
            self = .none
        case "apple":
            if let apple = AppleAttestation(cbor: statement) {
                self = .apple(apple)
            } else {
                self = .other(format: format, statement: statement)
            }
        default:
            self = .other(format: format, statement: statement)
        }
    }
}

// MARK: - PackedAttestation + CBOR

extension PackedAttestation: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: sig
        guard let sig: Data = map["sig"]?.cborDecoded() else {
            return nil
        }
        self.sig = sig

        // Required: alg
        guard let alg: Int = map["alg"]?.cborDecoded() else {
            return nil
        }
        self.alg = alg

        // Optional: x5c (certificate chain)
        self.x5c = map["x5c"]?.cborDecoded()

        // Optional: ecdaaKeyId (rarely used)
        self.ecdaaKeyId = map["ecdaaKeyId"]?.cborDecoded()
    }
}

// MARK: - FIDOU2FAttestation + CBOR

extension FIDOU2FAttestation: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: sig
        guard let sig: Data = map["sig"]?.cborDecoded() else {
            return nil
        }
        self.sig = sig

        // Required: x5c (certificate chain)
        guard let x5c: [Data] = map["x5c"]?.cborDecoded() else {
            return nil
        }
        self.x5c = x5c
    }
}

// MARK: - AppleAttestation + CBOR

extension AppleAttestation: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: x5c (certificate chain)
        guard let x5c: [Data] = map["x5c"]?.cborDecoded() else {
            return nil
        }
        self.x5c = x5c
    }
}
