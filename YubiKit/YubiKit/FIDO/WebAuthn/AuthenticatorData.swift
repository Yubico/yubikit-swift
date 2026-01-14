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
    /// Parsed authenticator data from FIDO2/WebAuthn operations.
    ///
    /// The authenticator data structure encodes contextual bindings made by the authenticator.
    /// It contains information about the relying party, flags, signature counter, and optionally
    /// attested credential data.
    ///
    /// - SeeAlso: [WebAuthn Authenticator Data](https://www.w3.org/TR/webauthn/#authenticator-data)
    public struct AuthenticatorData: Sendable {
        /// The raw authenticator data bytes.
        public let rawData: Data

        /// SHA-256 hash of the RP ID (32 bytes).
        public let rpIdHash: Data

        /// Flags indicating various states.
        public let flags: Flags

        /// Signature counter value (32-bit unsigned big-endian integer).
        public let signCount: UInt32

        /// Attested credential data (present when AT flag is set).
        public let attestedCredentialData: AttestedCredentialData?

        /// Raw extension outputs map (present when ED flag is set).
        ///
        /// Use extension-specific `result(from:)` methods for typed access to extension outputs.
        internal let extensions: [WebAuthn.Extension.Identifier: CBOR.Value]?

        /// Authenticator data flags.
        public struct Flags: OptionSet, Sendable {
            public let rawValue: UInt8

            public init(rawValue: UInt8) {
                self.rawValue = rawValue
            }

            /// User Present (UP): User was present during the operation.
            public static let userPresent = Flags(rawValue: 1 << 0)

            /// User Verified (UV): User was verified (PIN, biometric, etc.).
            public static let userVerified = Flags(rawValue: 1 << 2)

            /// Backup Eligibility (BE): Credential can be backed up.
            public static let backupEligibility = Flags(rawValue: 1 << 3)

            /// Backup State (BS): Credential is currently backed up.
            public static let backupState = Flags(rawValue: 1 << 4)

            /// Attested Credential Data (AT): Includes attested credential data.
            public static let attestedCredentialData = Flags(rawValue: 1 << 6)

            /// Extension Data (ED): Includes extension data.
            public static let extensionData = Flags(rawValue: 1 << 7)
        }
    }
}

// MARK: - Binary Parsing

extension WebAuthn.AuthenticatorData {
    /// Parse authenticator data from raw bytes.
    ///
    /// - Parameter data: The raw authenticator data bytes.
    /// - Returns: Parsed authenticator data, or nil if parsing fails.
    init?(data: Data) {
        // Minimum size: rpIdHash (32) + flags (1) + signCount (4) = 37 bytes
        guard data.count >= 37 else {
            return nil
        }

        // Store raw data for WebAuthn client use
        self.rawData = data

        var offset = 0

        // MARK: Parse RP ID Hash
        self.rpIdHash = data.subdata(in: offset..<(offset + 32))
        offset += 32

        // MARK: Parse Flags
        let flagsByte = data[offset]
        self.flags = Flags(rawValue: flagsByte)
        offset += 1

        // MARK: Parse Signature Counter
        let signCountData = data.subdata(in: offset..<(offset + 4))
        self.signCount = signCountData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        offset += 4

        // MARK: Parse Attested Credential Data (optional)
        if flags.contains(.attestedCredentialData) {
            guard let (attestedData, newOffset) = WebAuthn.AttestedCredentialData.parse(from: data, startingAt: offset)
            else {
                return nil
            }
            self.attestedCredentialData = attestedData
            offset = newOffset
        } else {
            self.attestedCredentialData = nil
        }

        // MARK: Parse Extensions (optional)
        if flags.contains(.extensionData) {
            // Extensions are CBOR-encoded as a map with string keys
            let extensionsData = data.subdata(in: offset..<data.count)
            guard let extensionsValue: CBOR.Value = try? extensionsData.decode(),
                let map = extensionsValue.mapValue
            else {
                return nil
            }
            // Convert CBOR map to [Identifier: CBOR.Value]
            var extensions: [WebAuthn.Extension.Identifier: CBOR.Value] = [:]
            for (key, value) in map {
                guard let identifier: WebAuthn.Extension.Identifier = key.cborDecoded() else {
                    return nil  // Extension keys must be strings
                }
                extensions[identifier] = value
            }
            self.extensions = extensions
        } else {
            self.extensions = nil
        }
    }
}

// MARK: - Attested Credential Data

extension WebAuthn {
    /// Attested credential data included in authenticator data during credential creation.
    ///
    /// Contains the AAGUID, credential ID, and credential public key.
    ///
    /// - SeeAlso: [WebAuthn Attested Credential Data](https://www.w3.org/TR/webauthn/#sctn-attested-credential-data)
    public struct AttestedCredentialData: Sendable {
        /// Authenticator Attestation GUID (16 bytes).
        public let aaguid: Data

        /// The credential ID (variable length).
        public let credentialId: Data

        /// The credential public key as a COSE Key.
        ///
        /// Structured representation of the COSE key from the authenticator.
        /// Unknown or unsupported algorithms are preserved in the `.other` case.
        ///
        /// Supported algorithms for FIDO2 on YubiKey:
        /// - ES256 (ECDSA with P-256, alg=-7)
        /// - EdDSA (Ed25519, alg=-8)
        /// - RS256 (RSA with SHA-256, alg=-257)
        ///
        /// - SeeAlso: [COSE Key Structure](https://www.rfc-editor.org/rfc/rfc8152.html#section-7)
        public let credentialPublicKey: COSE.Key
    }
}

// MARK: - Attested Credential Data Parsing

extension WebAuthn.AttestedCredentialData {
    /// Parse attested credential data from raw bytes.
    ///
    /// - Parameters:
    ///   - data: The raw data containing attested credential data.
    ///   - offset: The starting offset in the data.
    /// - Returns: Tuple of (parsed data, new offset), or nil if parsing fails.
    static func parse(from data: Data, startingAt offset: Int) -> (WebAuthn.AttestedCredentialData, Int)? {
        // Need at least: aaguid (16) + credIdLen (2) = 18 bytes
        guard data.count >= offset + 18 else {
            return nil
        }

        var currentOffset = offset

        // MARK: Parse AAGUID
        let aaguid = data.subdata(in: currentOffset..<(currentOffset + 16))
        currentOffset += 16

        // MARK: Parse Credential ID Length
        let credIdLengthData = data.subdata(in: currentOffset..<(currentOffset + 2))
        let credIdLength = Int(credIdLengthData[0]) << 8 | Int(credIdLengthData[1])
        currentOffset += 2

        // MARK: Parse Credential ID
        guard data.count >= currentOffset + credIdLength else {
            return nil
        }
        let credentialId = data.subdata(in: currentOffset..<(currentOffset + credIdLength))
        currentOffset += credIdLength

        // MARK: Parse Credential Public Key (CBOR)
        let cborData = data.subdata(in: currentOffset..<data.count)
        var remaining = Data()
        guard let coseKey: COSE.Key = try? cborData.decode(remaining: &remaining) else {
            return nil
        }
        currentOffset = data.count - remaining.count

        let attestedData = WebAuthn.AttestedCredentialData(
            aaguid: aaguid,
            credentialId: credentialId,
            credentialPublicKey: coseKey
        )

        return (attestedData, currentOffset)
    }
}
