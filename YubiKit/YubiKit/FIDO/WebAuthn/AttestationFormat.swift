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

extension WebAuthn {
    /// WebAuthn attestation statement format identifier.
    ///
    /// Identifies the format of an attestation statement, either in a
    /// `MakeCredential` response or as a supported format in `GetInfo`.
    ///
    /// - SeeAlso: [WebAuthn Attestation Statement Formats](https://www.w3.org/TR/webauthn/#sctn-attestation-formats)
    enum AttestationFormat: Sendable, Hashable {
        /// Packed attestation format - WebAuthn-optimized, compact encoding.
        case packed

        /// TPM attestation format - uses TPM-specific structures.
        case tpm

        /// Android Key attestation format - hardware attestation on Android N+.
        case androidKey

        /// Android SafetyNet attestation format.
        case androidSafetynet

        /// FIDO U2F attestation format.
        case fidoU2F

        /// Apple anonymous attestation format.
        case apple

        /// No attestation - used when RP doesn't want attestation info.
        case none

        /// Unknown or future attestation format.
        case unknown(String)

        /// The string representation of the format.
        var rawValue: String {
            switch self {
            case .packed: return "packed"
            case .tpm: return "tpm"
            case .androidKey: return "android-key"
            case .androidSafetynet: return "android-safetynet"
            case .fidoU2F: return "fido-u2f"
            case .apple: return "apple"
            case .none: return "none"
            case .unknown(let value): return value
            }
        }

        /// Initialize from a string value.
        init(rawValue: String) {
            switch rawValue {
            case "packed": self = .packed
            case "tpm": self = .tpm
            case "android-key": self = .androidKey
            case "android-safetynet": self = .androidSafetynet
            case "fido-u2f": self = .fidoU2F
            case "apple": self = .apple
            case "none": self = .none
            default: self = .unknown(rawValue)
            }
        }
    }
}

// MARK: - CBOR Conformance

extension WebAuthn.AttestationFormat: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let string: String = cbor.cborDecoded() else {
            return nil
        }
        self.init(rawValue: string)
    }
}

extension WebAuthn.AttestationFormat: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .textString(rawValue)
    }
}
