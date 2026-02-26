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
    internal struct ImmutableView: Sendable {

        let versions: [AuthenticatorVersion]
        let aaguid: AAGUID
        let extensions: [CTAP2.Extension.Identifier]
        let options: Options.ImmutableView
        let maxMsgSize: UInt
        let pinUVAuthProtocols: [CTAP2.ClientPin.ProtocolVersion]

        let maxCredentialCountInList: UInt?
        let maxCredentialIdLength: UInt?
        let transports: [WebAuthn.Transport]
        let algorithms: [COSE.Algorithm]
        let maxSerializedLargeBlobArray: UInt?
        let firmwareVersion: UInt?
        let maxCredBlobLength: UInt?
        let maxRPIDsForSetMinPinLength: UInt?
        let preferredPlatformUVAttempts: UInt?
        let uvModality: UVModality?
        let certifications: [String: UInt]
        let vendorPrototypeConfigCommands: [UInt]?
        let attestationFormats: [WebAuthn.AttestationFormat]
        let longTouchForReset: Bool?
        let transportsForReset: [WebAuthn.Transport]
        let pinComplexityPolicyURL: URL?
        let maxPINLength: UInt?
        let authenticatorConfigCommands: [CTAP2.Config.Subcommand]?

        init(_ response: Response) {
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
    internal struct ImmutableView: Sendable, CTAP2.GetInfo.Options.SupportChecking {

        // Immutable options
        let platformDevice: Bool
        let residentKey: Bool
        let userPresence: Bool

        // Tri-state support flags
        let supportsClientPin: Bool
        let supportsUserVerification: Bool
        let supportsEnterpriseAttestation: Bool
        let supportsBioEnroll: Bool
        let supportsAlwaysUV: Bool
        let supportsUserVerificationMgmtPreview: Bool

        // Binary options
        let pinUVAuthToken: Bool
        let noMcGaPermissionsWithClientPin: Bool
        let largeBlobs: Bool
        let uvBioEnroll: Bool
        let authenticatorConfig: Bool
        let uvAuthenticatorConfig: Bool
        let credentialManagement: Bool
        let setMinPINLength: Bool
        let perCredMgmtRO: Bool
        let credentialMgmtPreview: Bool

        init(_ options: CTAP2.GetInfo.Options) {
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
