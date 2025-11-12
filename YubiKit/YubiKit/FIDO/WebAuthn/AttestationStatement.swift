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

// MARK: - Attestation Statement

/// Attestation statement from the authenticator.
///
/// The structure varies by attestation format. This type provides strongly-typed
/// access to common formats, with a fallback for unknown formats.
///
/// - SeeAlso: [WebAuthn Attestation Statement Formats](https://www.w3.org/TR/webauthn/#sctn-attestation-formats)
enum AttestationStatement: Sendable {
    /// Packed attestation format (FIDO2).
    case packed(PackedAttestation)

    /// FIDO U2F attestation format.
    case fidoU2F(FIDOU2FAttestation)

    /// No attestation (self-attestation).
    case none

    /// Apple anonymous attestation.
    case apple(AppleAttestation)

    /// Unknown or unsupported attestation format.
    /// The format identifier is preserved for future compatibility.
    case unknown(format: String)

    /// The attestation format identifier.
    var format: String {
        switch self {
        case .packed: return "packed"
        case .fidoU2F: return "fido-u2f"
        case .none: return "none"
        case .apple: return "apple"
        case .unknown(let format): return format
        }
    }
}

// MARK: - Packed Attestation

/// Packed attestation statement.
///
/// - SeeAlso: [Packed Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-packed-attestation)
struct PackedAttestation: Sendable {
    /// Attestation signature.
    let sig: Data

    /// Signature algorithm (COSE algorithm identifier).
    let alg: Int

    /// Attestation certificate chain (optional for self-attestation).
    let x5c: [Data]?

    /// ECDAA-Issuer public key (optional, rarely used).
    let ecdaaKeyId: Data?
}

// MARK: - FIDO U2F Attestation

/// FIDO U2F attestation statement.
///
/// - SeeAlso: [FIDO U2F Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-fido-u2f-attestation)
struct FIDOU2FAttestation: Sendable {
    /// Attestation signature.
    let sig: Data

    /// Attestation certificate chain.
    let x5c: [Data]
}

// MARK: - Apple Attestation

/// Apple anonymous attestation statement.
///
/// - SeeAlso: [Apple Anonymous Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-apple-anonymous-attestation)
struct AppleAttestation: Sendable {
    /// Attestation certificate chain.
    let x5c: [Data]
}
