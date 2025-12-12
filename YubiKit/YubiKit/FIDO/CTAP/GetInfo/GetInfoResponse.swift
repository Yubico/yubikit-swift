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
    public typealias AAGUID = UUID

    /// CTAP/FIDO protocol version supported by an authenticator.
    public enum AuthenticatorVersion: Sendable, Equatable {
        case u2fV2
        case fido2_0
        case fido2_1Pre
        case fido2_1
        case unknown(String)

        public init(_ string: String) {
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
    public struct UVModality: OptionSet, Sendable, Hashable {
        public let rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// Authenticator can confirm user presence in any fashion.
        public static let presenceInternal = UVModality(rawValue: 0x0000_0001)

        /// Authenticator uses fingerprint measurement for verification.
        public static let fingerprintInternal = UVModality(rawValue: 0x0000_0002)

        /// Authenticator uses a local-only passcode for verification.
        public static let passcodeInternal = UVModality(rawValue: 0x0000_0004)

        /// Authenticator uses voiceprint (speaker recognition) for verification.
        public static let voiceprintInternal = UVModality(rawValue: 0x0000_0008)

        /// Authenticator uses face recognition for verification.
        public static let faceprintInternal = UVModality(rawValue: 0x0000_0010)

        /// Authenticator uses location sensor for verification.
        public static let locationInternal = UVModality(rawValue: 0x0000_0020)

        /// Authenticator uses eye biometrics for verification.
        public static let eyeprintInternal = UVModality(rawValue: 0x0000_0040)

        /// Authenticator uses a drawn pattern for verification.
        public static let patternInternal = UVModality(rawValue: 0x0000_0080)

        /// Authenticator uses full hand measurement for verification.
        public static let handprintInternal = UVModality(rawValue: 0x0000_0100)

        /// Authenticator will respond without any user interaction.
        public static let none = UVModality(rawValue: 0x0000_0200)

        /// All verification methods will be enforced (AND relationship).
        public static let all = UVModality(rawValue: 0x0000_0400)

        /// Passcode gathered outside the authenticator boundary.
        public static let passcodeExternal = UVModality(rawValue: 0x0000_0800)

        /// Drawn pattern gathered outside the authenticator boundary.
        public static let patternExternal = UVModality(rawValue: 0x0000_1000)
    }

    /// Information about a FIDO2/CTAP2 authenticator.
    ///
    /// This structure contains the response from the `authenticatorGetInfo` command,
    /// providing details about the authenticator's capabilities, supported features,
    /// and configuration.
    public struct Response: Sendable {

        // MARK: - Required Fields

        /// List of supported CTAP protocol versions.
        public let versions: [AuthenticatorVersion]

        /// The authenticator's AAGUID (Authenticator Attestation Global Unique ID).
        /// This is a 128-bit identifier that indicates the type/model of authenticator.
        public let aaguid: AAGUID

        /// List of supported extensions (e.g., `.hmacSecret`, `.credProtect`).
        public let extensions: [CTAP2.Extension.Identifier]

        /// Supported authenticator options with their current values.
        public let options: Options

        /// Maximum message size supported by the authenticator in bytes.
        public let maxMsgSize: UInt

        /// List of supported PIN/UV authentication protocol versions.
        public let pinUVAuthProtocols: [CTAP2.ClientPin.ProtocolVersion]

        // MARK: - Optional Fields

        /// Maximum number of credentials that can be sent in allowList.
        public let maxCredentialCountInList: UInt?

        /// Maximum length of credential ID in bytes.
        public let maxCredentialIdLength: UInt?

        /// Supported transports (e.g., usb, nfc, ble).
        public let transports: [CTAP2.Transport]

        /// List of supported cryptographic algorithms.
        public let algorithms: [COSE.Algorithm]

        /// Maximum size of serialized large blob array in bytes.
        public let maxSerializedLargeBlobArray: UInt?

        /// Indicates if PIN change is required before further operations.
        public let forcePinChange: Bool?

        /// Minimum PIN length required by the authenticator.
        public let minPinLength: UInt?

        /// Firmware version number.
        public let firmwareVersion: UInt?

        /// Maximum length of credential blob in bytes.
        public let maxCredBlobLength: UInt?

        /// Maximum number of RP IDs for setMinPINLength.
        public let maxRPIDsForSetMinPinLength: UInt?

        /// Preferred number of platform UV attempts.
        public let preferredPlatformUVAttempts: UInt?

        /// User verification methods supported by this authenticator.
        public let uvModality: UVModality?

        /// Authenticator certifications (certification name -> level).
        ///
        /// Provides hints about certifications the authenticator has received.
        /// Examples include FIPS-CMVP, Common Criteria, and FIDO certifications.
        ///
        /// - SeeAlso: [CTAP 2.3 Section 7.3](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-feature-descriptions-certifications)
        public let certifications: [String: UInt]

        /// Remaining discoverable credential slots.
        public let remainingDiscoverableCredentials: UInt?

        /// Supported vendor prototype config commands.
        public let vendorPrototypeConfigCommands: [UInt]?

        /// Supported attestation statement format identifiers (e.g., `.packed`, `.tpm`).
        public let attestationFormats: [WebAuthn.AttestationFormat]

        /// Number of internal UV operations since the last PIN entry.
        ///
        /// Allows the platform to periodically prompt for PIN on biometric devices
        /// so users don't forget it.
        public let uvCountSinceLastPinEntry: UInt?

        /// Whether the authenticator requires a 10-second touch for reset.
        public let longTouchForReset: Bool?

        /// Encrypted device identifier (decryptable with a persistent PUAT).
        ///
        /// The value contains `iv || ct` where `ct` is the AES-128-CBC encryption
        /// of a 128-bit device identifier.
        public let encIdentifier: Data?

        /// Transports that support the reset command.
        public let transportsForReset: [CTAP2.Transport]

        /// Whether PIN complexity policy is enforced.
        ///
        /// When `true`, the authenticator enforces PIN complexity rules beyond
        /// just minimum length.
        public let pinComplexityPolicy: Bool?

        /// URL containing PIN complexity policy details.
        public let pinComplexityPolicyURL: URL?

        /// Maximum PIN length supported by the authenticator.
        public let maxPINLength: UInt?

    }
}
