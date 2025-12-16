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

extension CTAP2.GetInfo {
    /// Authenticator Attestation Global Unique ID (128-bit identifier).
    typealias AAGUID = UUID

    /// CTAP/FIDO protocol version supported by an authenticator.
    enum AuthenticatorVersion: Sendable, Equatable {
        case u2fV2
        case fido2_0
        case fido2_1Pre
        case fido2_1
        case unknown(String)

        init(_ string: String) {
            switch string {
            case "U2F_V2": self = .u2fV2
            case "FIDO_2_0": self = .fido2_0
            case "FIDO_2_1_PRE": self = .fido2_1Pre
            case "FIDO_2_1": self = .fido2_1
            default: self = .unknown(string)
            }
        }
    }

    /// User verification methods supported by an authenticator.
    ///
    /// This is a bitmask indicating which verification methods the authenticator supports.
    ///
    /// - SeeAlso: [FIDO Registry Section 3.1](https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods)
    struct UVModality: OptionSet, Sendable, Hashable {
        let rawValue: UInt32

        /// Authenticator can confirm user presence in any fashion.
        static let presenceInternal = UVModality(rawValue: 0x0000_0001)

        /// Authenticator uses fingerprint measurement for verification.
        static let fingerprintInternal = UVModality(rawValue: 0x0000_0002)

        /// Authenticator uses a local-only passcode for verification.
        static let passcodeInternal = UVModality(rawValue: 0x0000_0004)

        /// Authenticator uses voiceprint (speaker recognition) for verification.
        static let voiceprintInternal = UVModality(rawValue: 0x0000_0008)

        /// Authenticator uses face recognition for verification.
        static let faceprintInternal = UVModality(rawValue: 0x0000_0010)

        /// Authenticator uses location sensor for verification.
        static let locationInternal = UVModality(rawValue: 0x0000_0020)

        /// Authenticator uses eye biometrics for verification.
        static let eyeprintInternal = UVModality(rawValue: 0x0000_0040)

        /// Authenticator uses a drawn pattern for verification.
        static let patternInternal = UVModality(rawValue: 0x0000_0080)

        /// Authenticator uses full hand measurement for verification.
        static let handprintInternal = UVModality(rawValue: 0x0000_0100)

        /// Authenticator will respond without any user interaction.
        static let none = UVModality(rawValue: 0x0000_0200)

        /// All verification methods will be enforced (AND relationship).
        static let all = UVModality(rawValue: 0x0000_0400)

        /// Passcode gathered outside the authenticator boundary.
        static let passcodeExternal = UVModality(rawValue: 0x0000_0800)

        /// Drawn pattern gathered outside the authenticator boundary.
        static let patternExternal = UVModality(rawValue: 0x0000_1000)
    }

    /// Information about a FIDO2/CTAP2 authenticator.
    ///
    /// This structure contains the response from the `authenticatorGetInfo` command,
    /// providing details about the authenticator's capabilities, supported features,
    /// and configuration.
    struct Response: Sendable {

        // MARK: - Required Fields

        /// List of supported CTAP protocol versions.
        let versions: [AuthenticatorVersion]

        /// The authenticator's AAGUID (Authenticator Attestation Global Unique ID).
        /// This is a 128-bit identifier that indicates the type/model of authenticator.
        let aaguid: AAGUID

        /// List of supported extensions (e.g., `.hmacSecret`, `.credProtect`).
        let extensions: [CTAP2.Extension.Identifier]

        /// Supported authenticator options with their current values.
        let options: Options

        /// Maximum message size supported by the authenticator in bytes.
        let maxMsgSize: UInt

        /// List of supported PIN/UV authentication protocol versions.
        let pinUVAuthProtocols: [CTAP2.ClientPin.ProtocolVersion]

        // MARK: - Optional Fields

        /// Maximum number of credentials that can be sent in allowList.
        let maxCredentialCountInList: UInt?

        /// Maximum length of credential ID in bytes.
        let maxCredentialIdLength: UInt?

        /// Supported transports (e.g., usb, nfc, ble).
        let transports: [CTAP2.Transport]

        /// List of supported cryptographic algorithms.
        let algorithms: [COSE.Algorithm]

        /// Maximum size of serialized large blob array in bytes.
        let maxSerializedLargeBlobArray: UInt?

        /// Indicates if PIN change is required before further operations.
        let forcePinChange: Bool?

        /// Minimum PIN length required by the authenticator.
        let minPinLength: UInt?

        /// Firmware version number.
        let firmwareVersion: UInt?

        /// Maximum length of credential blob in bytes.
        let maxCredBlobLength: UInt?

        /// Maximum number of RP IDs for setMinPINLength.
        let maxRPIDsForSetMinPinLength: UInt?

        /// Preferred number of platform UV attempts.
        let preferredPlatformUVAttempts: UInt?

        /// User verification methods supported by this authenticator.
        let uvModality: UVModality?

        /// Authenticator certifications (certification name -> level).
        ///
        /// Provides hints about certifications the authenticator has received.
        /// Examples include FIPS-CMVP, Common Criteria, and FIDO certifications.
        ///
        /// - SeeAlso: [CTAP 2.3 Section 7.3](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-feature-descriptions-certifications)
        let certifications: [String: UInt]

        /// Remaining discoverable credential slots.
        let remainingDiscoverableCredentials: UInt?

        /// Supported vendor prototype config commands.
        let vendorPrototypeConfigCommands: [UInt]?

        /// Supported attestation statement format identifiers (e.g., `.packed`, `.tpm`).
        let attestationFormats: [WebAuthn.AttestationFormat]

        /// Number of internal UV operations since the last PIN entry.
        ///
        /// Allows the platform to periodically prompt for PIN on biometric devices
        /// so users don't forget it.
        let uvCountSinceLastPinEntry: UInt?

        /// Whether the authenticator requires a 10-second touch for reset.
        let longTouchForReset: Bool?

        /// Encrypted device identifier (decryptable with a persistent PUAT).
        ///
        /// The value contains `iv || ct` where `ct` is the AES-128-CBC encryption
        /// of a 128-bit device identifier.
        let encIdentifier: Data?

        /// Transports that support the reset command.
        let transportsForReset: [CTAP2.Transport]

        /// Whether PIN complexity policy is enforced.
        ///
        /// When `true`, the authenticator enforces PIN complexity rules beyond
        /// just minimum length.
        let pinComplexityPolicy: Bool?

        /// URL containing PIN complexity policy details.
        let pinComplexityPolicyURL: URL?

        /// Maximum PIN length supported by the authenticator.
        let maxPINLength: UInt?

    }
}
