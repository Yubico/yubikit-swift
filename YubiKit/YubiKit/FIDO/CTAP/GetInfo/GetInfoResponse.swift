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

extension CTAP.GetInfo {
    /// Information about a FIDO2/CTAP2 authenticator.
    ///
    /// This structure contains the response from the `authenticatorGetInfo` command,
    /// providing details about the authenticator's capabilities, supported features,
    /// and configuration.
    struct Response: Sendable {

        // MARK: - Required Fields

        /// List of supported CTAP protocol versions (e.g., "FIDO_2_0", "FIDO_2_1").
        let versions: [String]

        /// The authenticator's AAGUID (Authenticator Attestation Global Unique ID).
        /// This is a 128-bit identifier that indicates the type/model of authenticator.
        let aaguid: Data

        /// List of supported extensions (e.g., "hmac-secret", "credProtect").
        let extensions: [String]

        /// Supported authenticator options with their current values.
        let options: [String: Bool]

        /// Maximum message size supported by the authenticator in bytes.
        let maxMsgSize: UInt

        /// List of supported PIN/UV authentication protocol versions.
        let pinUvAuthProtocols: [UInt]

        // MARK: - Optional Fields

        /// Maximum number of credentials that can be sent in allowList.
        let maxCredentialCountInList: UInt?

        /// Maximum length of credential ID in bytes.
        let maxCredentialIdLength: UInt?

        /// Supported transports (e.g., "usb", "nfc", "ble").
        let transports: [String]?

        /// List of supported cryptographic algorithms (COSE algorithm identifiers).
        let algorithms: [Int]?

        /// Maximum size of serialized large blob array in bytes.
        let maxSerializedLargeBlobArray: UInt?

        /// Indicates if PIN change is required before further operations.
        let forcePINChange: Bool?

        /// Minimum PIN length required by the authenticator.
        let minPINLength: UInt?

        /// Firmware version number.
        let firmwareVersion: UInt?

        /// Maximum length of credential blob in bytes.
        let maxCredBlobLength: UInt?

        /// Maximum number of RP IDs for setMinPINLength.
        let maxRPIDsForSetMinPINLength: UInt?

        /// Preferred number of platform UV attempts.
        let preferredPlatformUvAttempts: UInt?

        /// User verification modality.
        let uvModality: UInt?

        /// Authenticator certifications (certification name -> level).
        ///
        /// Provides hints about certifications the authenticator has received.
        /// Examples include FIPS-CMVP, Common Criteria, and FIDO certifications.
        ///
        /// - SeeAlso: [CTAP 2.3 Section 7.3](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-feature-descriptions-certifications)
        let certifications: [String: UInt]?

        /// Remaining discoverable credential slots.
        let remainingDiscoverableCredentials: UInt?

        /// Supported vendor prototype config commands.
        let vendorPrototypeConfigCommands: [UInt]?

        // MARK: - Initialization

        init(
            versions: [String],
            aaguid: Data,
            extensions: [String] = [],
            options: [String: Bool] = [:],
            maxMsgSize: UInt = 1024,
            pinUvAuthProtocols: [UInt] = [],
            maxCredentialCountInList: UInt? = nil,
            maxCredentialIdLength: UInt? = nil,
            transports: [String]? = nil,
            algorithms: [Int]? = nil,
            maxSerializedLargeBlobArray: UInt? = nil,
            forcePINChange: Bool? = nil,
            minPINLength: UInt? = nil,
            firmwareVersion: UInt? = nil,
            maxCredBlobLength: UInt? = nil,
            maxRPIDsForSetMinPINLength: UInt? = nil,
            preferredPlatformUvAttempts: UInt? = nil,
            uvModality: UInt? = nil,
            certifications: [String: UInt]? = nil,
            remainingDiscoverableCredentials: UInt? = nil,
            vendorPrototypeConfigCommands: [UInt]? = nil
        ) {
            self.versions = versions
            self.aaguid = aaguid
            self.extensions = extensions
            self.options = options
            self.maxMsgSize = maxMsgSize
            self.pinUvAuthProtocols = pinUvAuthProtocols
            self.maxCredentialCountInList = maxCredentialCountInList
            self.maxCredentialIdLength = maxCredentialIdLength
            self.transports = transports
            self.algorithms = algorithms
            self.maxSerializedLargeBlobArray = maxSerializedLargeBlobArray
            self.forcePINChange = forcePINChange
            self.minPINLength = minPINLength
            self.firmwareVersion = firmwareVersion
            self.maxCredBlobLength = maxCredBlobLength
            self.maxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength
            self.preferredPlatformUvAttempts = preferredPlatformUvAttempts
            self.uvModality = uvModality
            self.certifications = certifications
            self.remainingDiscoverableCredentials = remainingDiscoverableCredentials
            self.vendorPrototypeConfigCommands = vendorPrototypeConfigCommands
        }
    }
}
