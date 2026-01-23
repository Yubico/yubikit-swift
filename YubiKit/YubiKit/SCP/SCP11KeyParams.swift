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

/// Key parameters for Secure Channel Protocol 11 (SCP11).
/// Contains the key reference and cryptographic materials needed for establishing an SCP11 secure channel.
/// Supports three variants: SCP11a, SCP11b, and SCP11c with different key requirements.
public struct SCP11KeyParams: SCPKeyParams, Sendable {

    /// The key reference containing key ID and version.
    public let keyRef: SCPKeyRef

    /// The public key of the SD (Security Domain) for ECKA (Elliptic Curve Key Agreement).
    public let pkSdEcka: EC.PublicKey

    /// The optional OCE (Off-Card Entity) key reference (required for SCP11a/c, nil for SCP11b).
    public let oceKeyRef: SCPKeyRef?

    /// The optional OCE private key for ECKA (required for SCP11a/c, nil for SCP11b).
    public let skOceEcka: EC.PrivateKey?

    /// The certificate chain (required for SCP11a/c, empty for SCP11b).
    public let certificates: [X509Cert]

    /// Creates SCP11 key parameters.
    /// - Parameters:
    ///   - keyRef: The key reference with KID (0x11 for SCP11a, 0x13 for SCP11b, 0x15 for SCP11c) and KVN.
    ///   - pkSdEcka: The public key of the Security Domain for ECKA.
    ///   - oceKeyRef: The OCE key reference (required for SCP11a/c, must be nil for SCP11b).
    ///   - skOceEcka: The OCE private key for ECKA (required for SCP11a/c, must be nil for SCP11b).
    ///   - certificates: The certificate chain (required for SCP11a/c, must be empty for SCP11b).
    /// - Throws: ``SCPError/illegalArgument(_:source:)`` if the parameters don't match the SCP11 variant requirements.
    public init(
        keyRef: SCPKeyRef,
        pkSdEcka: EC.PublicKey,
        oceKeyRef: SCPKeyRef? = nil,
        skOceEcka: EC.PrivateKey? = nil,
        certificates: [X509Cert] = []
    ) throws(SCPError) {
        switch keyRef.kid {
        case .scp11b:
            if oceKeyRef != nil || skOceEcka != nil || !certificates.isEmpty {
                throw .illegalArgument(
                    "Cannot provide oceKeyRef, skOceEcka or certificates for SCP11b",
                    source: .here()
                )
            }
        case .scp11a, .scp11c:
            if oceKeyRef == nil || skOceEcka == nil || certificates.isEmpty {
                throw .illegalArgument(
                    "Must provide oceKeyRef, skOceEcka or certificates for SCP11a/c",
                    source: .here()
                )
            }
        default:
            throw .illegalArgument("KID must be 0x11, 0x13, or 0x15 for SCP11", source: .here())
        }
        self.keyRef = keyRef
        self.pkSdEcka = pkSdEcka
        self.oceKeyRef = oceKeyRef
        self.skOceEcka = skOceEcka
        self.certificates = certificates
    }
}
