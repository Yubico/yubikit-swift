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

    /// Cached view of immutable GetInfo fields (capabilities, limits, supported features).
    ///
    /// Mutable fields (forcePinChange, remainingDiscoverableCredentials, etc.) are excluded.
    /// Use ``CTAP2/Session/getInfo()`` to read current mutable state.
    public struct ImmutableView: Sendable {

        public let versions: [AuthenticatorVersion]
        public let aaguid: AAGUID
        public let extensions: [CTAP2.Extension.Identifier]
        public let options: Options.ImmutableView
        public let maxMsgSize: UInt
        public let pinUVAuthProtocols: [CTAP2.ClientPin.ProtocolVersion]

        public let maxCredentialCountInList: UInt?
        public let maxCredentialIdLength: UInt?
        public let transports: [WebAuthn.Transport]
        public let algorithms: [COSE.Algorithm]
        public let maxSerializedLargeBlobArray: UInt?
        public let firmwareVersion: UInt?
        public let maxCredBlobLength: UInt?
        public let maxRPIDsForSetMinPinLength: UInt?
        public let preferredPlatformUVAttempts: UInt?
        public let uvModality: UVModality?
        public let certifications: [String: UInt]
        public let vendorPrototypeConfigCommands: [UInt]?
        public let attestationFormats: [WebAuthn.AttestationFormat]
        public let longTouchForReset: Bool?
        public let transportsForReset: [WebAuthn.Transport]
        public let pinComplexityPolicyURL: URL?
        public let maxPINLength: UInt?
        public let authenticatorConfigCommands: [CTAP2.Config.Subcommand]?

        public init(_ response: Response) {
            self.versions = response.versions
            self.aaguid = response.aaguid
            self.extensions = response.extensions
            self.options = Options.ImmutableView(response.options)
            self.maxMsgSize = response.maxMsgSize
            self.pinUVAuthProtocols = response.pinUVAuthProtocols
            self.maxCredentialCountInList = response.maxCredentialCountInList
            self.maxCredentialIdLength = response.maxCredentialIdLength
            self.transports = response.transports
            self.algorithms = response.algorithms
            self.maxSerializedLargeBlobArray = response.maxSerializedLargeBlobArray
            self.firmwareVersion = response.firmwareVersion
            self.maxCredBlobLength = response.maxCredBlobLength
            self.maxRPIDsForSetMinPinLength = response.maxRPIDsForSetMinPinLength
            self.preferredPlatformUVAttempts = response.preferredPlatformUVAttempts
            self.uvModality = response.uvModality
            self.certifications = response.certifications
            self.vendorPrototypeConfigCommands = response.vendorPrototypeConfigCommands
            self.attestationFormats = response.attestationFormats
            self.longTouchForReset = response.longTouchForReset
            self.transportsForReset = response.transportsForReset
            self.pinComplexityPolicyURL = response.pinComplexityPolicyURL
            self.maxPINLength = response.maxPINLength
            self.authenticatorConfigCommands = response.authenticatorConfigCommands
        }
    }
}

// MARK: - Immutable Options

extension CTAP2.GetInfo.Options {
    /// Cached view of immutable options (always-constant values + feature support flags).
    ///
    /// For current mutable option state, use ``CTAP2/Session/getInfo()``.
    public struct ImmutableView: Sendable, CTAP2.GetInfo.Options.SupportChecking {

        // Immutable options
        public let platformDevice: Bool
        public let residentKey: Bool
        public let userPresence: Bool

        // Tri-state support flags
        public let supportsClientPin: Bool
        public let supportsUserVerification: Bool
        public let supportsEnterpriseAttestation: Bool
        public let supportsBioEnroll: Bool
        public let supportsAlwaysUV: Bool
        public let supportsUserVerificationMgmtPreview: Bool

        // Binary options
        public let pinUVAuthToken: Bool
        public let noMcGaPermissionsWithClientPin: Bool
        public let largeBlobs: Bool
        public let uvBioEnroll: Bool
        public let authenticatorConfig: Bool
        public let uvAuthenticatorConfig: Bool
        public let credentialManagement: Bool
        public let setMinPINLength: Bool
        public let perCredMgmtRO: Bool
        public let credentialMgmtPreview: Bool

        public init(_ options: CTAP2.GetInfo.Options) {
            self.platformDevice = options.platformDevice
            self.residentKey = options.residentKey
            self.userPresence = options.userPresence

            self.supportsClientPin = options.supportsClientPin
            self.supportsUserVerification = options.supportsUserVerification
            self.supportsEnterpriseAttestation = options.supportsEnterpriseAttestation
            self.supportsBioEnroll = options.supportsBioEnroll
            self.supportsAlwaysUV = options.supportsAlwaysUV
            self.supportsUserVerificationMgmtPreview = options.supportsUserVerificationMgmtPreview

            self.pinUVAuthToken = options.pinUVAuthToken ?? false
            self.noMcGaPermissionsWithClientPin = options.noMcGaPermissionsWithClientPin ?? false
            self.largeBlobs = options.largeBlobs ?? false
            self.uvBioEnroll = options.uvBioEnroll ?? false
            self.authenticatorConfig = options.authenticatorConfig ?? false
            self.uvAuthenticatorConfig = options.uvAuthenticatorConfig ?? false
            self.credentialManagement = options.credentialManagement ?? false
            self.setMinPINLength = options.setMinPINLength ?? false
            self.perCredMgmtRO = options.perCredMgmtRO ?? false
            self.credentialMgmtPreview = options.credentialMgmtPreview ?? false
        }
    }
}
