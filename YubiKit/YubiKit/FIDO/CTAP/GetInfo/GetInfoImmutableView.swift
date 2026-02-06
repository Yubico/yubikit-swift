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

    /// A cached view of GetInfo fields that do not change during a ``CTAP2/Session``.
    ///
    /// These values describe fixed authenticator capabilities and limits.
    /// Mutable state fields (e.g. `forcePinChange`,
    /// `remainingDiscoverableCredentials`, `encIdentifier`) are excluded — use
    /// ``CTAP2/Session/getInfo()`` to read current mutable state.
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

        // MARK: - Init

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

// MARK: - Immutable Options View

extension CTAP2.GetInfo.Options {
    /// A view of authenticator options that do not change during a ``CTAP2/Session``.
    ///
    /// Mutable state flags (e.g. `clientPin`, `alwaysUV`, `bioEnroll`)
    /// are excluded — use ``CTAP2/Session/getInfo()`` to read current mutable state.
    internal struct ImmutableView: Sendable {

        let platformDevice: Bool
        let residentKey: Bool
        let userPresence: Bool
        let pinUVAuthToken: Bool?
        let noMcGaPermissionsWithClientPin: Bool?
        let largeBlobs: Bool?
        let authenticatorConfig: Bool?
        let uvAuthenticatorConfig: Bool?
        let credentialManagement: Bool?
        let setMinPINLength: Bool?
        let perCredMgmtRO: Bool?
        let credentialMgmtPreview: Bool?

        init(_ options: CTAP2.GetInfo.Options) {
            self.platformDevice = options.platformDevice
            self.residentKey = options.residentKey
            self.userPresence = options.userPresence
            self.pinUVAuthToken = options.pinUVAuthToken
            self.noMcGaPermissionsWithClientPin = options.noMcGaPermissionsWithClientPin
            self.largeBlobs = options.largeBlobs
            self.authenticatorConfig = options.authenticatorConfig
            self.uvAuthenticatorConfig = options.uvAuthenticatorConfig
            self.credentialManagement = options.credentialManagement
            self.setMinPINLength = options.setMinPINLength
            self.perCredMgmtRO = options.perCredMgmtRO
            self.credentialMgmtPreview = options.credentialMgmtPreview
        }
    }
}
