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

// MARK: - Attestation Format

extension WebAuthn {
    /// WebAuthn [attestation statement format](https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats)
    /// identifier.
    ///
    /// Identifies the format of an attestation statement, either in a
    /// `MakeCredential` response or as a supported format in `GetInfo`.
    public enum AttestationFormat: Sendable, Hashable {
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
        public var rawValue: String {
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
        public init(rawValue: String) {
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

// MARK: - Attestation Statement

extension WebAuthn {
    /// [Attestation statement](https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats)
    /// from the authenticator.
    ///
    /// The structure varies by attestation format. This type provides strongly-typed
    /// access to common formats, with a fallback for unknown formats.
    public enum AttestationStatement: Sendable {
        /// Packed attestation format (FIDO2).
        case packed(Packed)

        /// FIDO U2F attestation format.
        case fidoU2F(FIDOU2F)

        /// No attestation (self-attestation).
        case none

        /// Apple anonymous attestation.
        case apple(Apple)

        /// Unknown or unsupported attestation format.
        /// The format identifier is preserved for future compatibility.
        case unknown(format: String)

        /// The attestation format identifier.
        public var format: AttestationFormat {
            switch self {
            case .packed: return .packed
            case .fidoU2F: return .fidoU2F
            case .none: return .none
            case .apple: return .apple
            case .unknown(let format): return .unknown(format)
            }
        }
    }
}

// MARK: - Format Types

extension WebAuthn.AttestationStatement {

    /// [Packed attestation statement](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation).
    public struct Packed: Sendable {
        /// Attestation signature.
        public let sig: Data

        /// Signature algorithm (COSE algorithm identifier).
        public let alg: Int

        /// Attestation certificate chain (optional for self-attestation).
        public let x5c: [Data]?

        /// ECDAA-Issuer public key (optional, rarely used).
        public let ecdaaKeyId: Data?
    }

    /// [FIDO U2F attestation statement](https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation).
    public struct FIDOU2F: Sendable {
        /// Attestation signature.
        public let sig: Data

        /// Attestation certificate chain.
        public let x5c: [Data]
    }

    /// [Apple anonymous attestation statement](https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation).
    public struct Apple: Sendable {
        /// Attestation certificate chain.
        public let x5c: [Data]
    }
}
