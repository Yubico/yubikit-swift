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
    /// Authenticator options returned by the `authenticatorGetInfo` command.
    ///
    /// Options indicate the authenticator's capabilities and current configuration.
    /// Some options are tri-state: `true` (enabled), `false` (supported but not configured),
    /// or `nil` (not supported).
    struct Options: Sendable, Equatable {

        // MARK: - CTAP 2.0 Options

        /// Indicates the device is attached to the client and cannot be removed.
        ///
        /// If `true`, the authenticator is a platform authenticator (built into the client device).
        /// If `false` or absent, it's a roaming authenticator.
        let platformDevice: Bool

        /// Indicates the device supports resident keys (discoverable credentials).
        ///
        /// If `true`, the authenticator can store credentials on-device.
        let residentKey: Bool

        /// Indicates the device is capable of testing user presence.
        ///
        /// Defaults to `true` if absent.
        let userPresence: Bool

        /// Client PIN support status.
        ///
        /// - `true`: PIN is supported and has been set
        /// - `false`: PIN is supported but not yet set
        /// - `nil`: PIN is not supported
        let clientPin: Bool?

        /// Built-in user verification support status.
        ///
        /// - `true`: UV is supported and configured (e.g., biometric enrolled)
        /// - `false`: UV is supported but not yet configured
        /// - `nil`: UV is not supported (device can only do Client PIN)
        let userVerification: Bool?

        // MARK: - CTAP 2.1 Options

        /// Indicates support for `getPinUVAuthTokenUsingPinWithPermissions` and
        /// `getPinUVAuthTokenUsingUVWithPermissions` subcommands.
        ///
        /// When `true`:
        /// - If `clientPin` is `true`, supports `getPinUVAuthTokenUsingPinWithPermissions`
        /// - If `userVerification` is `true`, supports `getPinUVAuthTokenUsingUVWithPermissions`
        ///
        /// When `false` or absent, only legacy `getPinToken` is supported.
        let pinUvAuthToken: Bool?

        /// Indicates that tokens obtained via PIN cannot be used for MakeCredential/GetAssertion.
        ///
        /// When `true`, platforms should not attempt `getPinUVAuthTokenUsingPinWithPermissions`
        /// if `getPinUVAuthTokenUsingUVWithPermissions` fails.
        let noMcGaPermissionsWithClientPin: Bool?

        /// Indicates support for the `authenticatorLargeBlobs` command.
        let largeBlobs: Bool?

        /// Enterprise Attestation support status.
        ///
        /// - `true`: Supported and enabled
        /// - `false`: Supported but disabled
        /// - `nil`: Not supported
        let enterpriseAttestation: Bool?

        /// Biometric enrollment support status.
        ///
        /// - `true`: Supported with at least one enrollment provisioned
        /// - `false`: Supported but no enrollments yet
        /// - `nil`: Not supported
        let bioEnroll: Bool?

        /// Indicates support for requesting `be` permission via UV.
        ///
        /// Only present if `bioEnroll` is also present.
        let uvBioEnroll: Bool?

        /// Indicates support for the `authenticatorConfig` command.
        let authenticatorConfig: Bool?

        /// Indicates support for requesting `acfg` permission via UV.
        ///
        /// Only present if `authenticatorConfig` is also present.
        let uvAuthenticatorConfig: Bool?

        /// Indicates support for the `authenticatorCredentialManagement` command.
        let credentialManagement: Bool?

        /// Indicates support for the `setMinPINLength` subcommand.
        ///
        /// Only present if `clientPin` is also present.
        let setMinPINLength: Bool?

        /// Indicates non-discoverable credentials can be created without user verification.
        ///
        /// When `true`, the authenticator allows creating non-discoverable credentials
        /// without requiring any form of user verification if the platform requests it.
        let makeCredUvNotRequired: Bool?

        /// Always Require User Verification feature status.
        ///
        /// - `true`: Supported and enabled
        /// - `false`: Supported but disabled
        /// - `nil`: Not supported
        ///
        /// If `true`, `makeCredUvNotRequired` must be `false`.
        let alwaysUv: Bool?

        // MARK: - Preview/Prototype Options

        /// Prototype biometric enrollment support (FIDO_2_1_PRE).
        let userVerificationMgmtPreview: Bool?

        /// Prototype credential management support (FIDO_2_1_PRE).
        let credentialMgmtPreview: Bool?

        // MARK: - Default

        /// Default options matching CTAP2 spec defaults.
        static let `default` = Options(
            platformDevice: false,
            residentKey: false,
            userPresence: true,
            clientPin: nil,
            userVerification: nil,
            pinUvAuthToken: nil,
            noMcGaPermissionsWithClientPin: nil,
            largeBlobs: nil,
            enterpriseAttestation: nil,
            bioEnroll: nil,
            uvBioEnroll: nil,
            authenticatorConfig: nil,
            uvAuthenticatorConfig: nil,
            credentialManagement: nil,
            setMinPINLength: nil,
            makeCredUvNotRequired: nil,
            alwaysUv: nil,
            userVerificationMgmtPreview: nil,
            credentialMgmtPreview: nil
        )

        // MARK: - Initialization

        init(
            platformDevice: Bool,
            residentKey: Bool,
            userPresence: Bool,
            clientPin: Bool?,
            userVerification: Bool?,
            pinUvAuthToken: Bool?,
            noMcGaPermissionsWithClientPin: Bool?,
            largeBlobs: Bool?,
            enterpriseAttestation: Bool?,
            bioEnroll: Bool?,
            uvBioEnroll: Bool?,
            authenticatorConfig: Bool?,
            uvAuthenticatorConfig: Bool?,
            credentialManagement: Bool?,
            setMinPINLength: Bool?,
            makeCredUvNotRequired: Bool?,
            alwaysUv: Bool?,
            userVerificationMgmtPreview: Bool?,
            credentialMgmtPreview: Bool?
        ) {
            self.platformDevice = platformDevice
            self.residentKey = residentKey
            self.userPresence = userPresence
            self.clientPin = clientPin
            self.userVerification = userVerification
            self.pinUvAuthToken = pinUvAuthToken
            self.noMcGaPermissionsWithClientPin = noMcGaPermissionsWithClientPin
            self.largeBlobs = largeBlobs
            self.enterpriseAttestation = enterpriseAttestation
            self.bioEnroll = bioEnroll
            self.uvBioEnroll = uvBioEnroll
            self.authenticatorConfig = authenticatorConfig
            self.uvAuthenticatorConfig = uvAuthenticatorConfig
            self.credentialManagement = credentialManagement
            self.setMinPINLength = setMinPINLength
            self.makeCredUvNotRequired = makeCredUvNotRequired
            self.alwaysUv = alwaysUv
            self.userVerificationMgmtPreview = userVerificationMgmtPreview
            self.credentialMgmtPreview = credentialMgmtPreview
        }
    }
}

// MARK: - CBOR Decoding

extension CTAP2.GetInfo.Options: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        self.init(
            platformDevice: map[.textString("plat")]?.boolValue ?? false,
            residentKey: map[.textString("rk")]?.boolValue ?? false,
            userPresence: map[.textString("up")]?.boolValue ?? true,
            clientPin: map[.textString("clientPin")]?.boolValue,
            userVerification: map[.textString("uv")]?.boolValue,
            pinUvAuthToken: map[.textString("pinUvAuthToken")]?.boolValue,
            noMcGaPermissionsWithClientPin: map[.textString("noMcGaPermissionsWithClientPin")]?.boolValue,
            largeBlobs: map[.textString("largeBlobs")]?.boolValue,
            enterpriseAttestation: map[.textString("ep")]?.boolValue,
            bioEnroll: map[.textString("bioEnroll")]?.boolValue,
            uvBioEnroll: map[.textString("uvBioEnroll")]?.boolValue,
            authenticatorConfig: map[.textString("authnrCfg")]?.boolValue,
            uvAuthenticatorConfig: map[.textString("uvAcfg")]?.boolValue,
            credentialManagement: map[.textString("credMgmt")]?.boolValue,
            setMinPINLength: map[.textString("setMinPINLength")]?.boolValue,
            makeCredUvNotRequired: map[.textString("makeCredUvNotRqd")]?.boolValue,
            alwaysUv: map[.textString("alwaysUv")]?.boolValue,
            userVerificationMgmtPreview: map[.textString("userVerificationMgmtPreview")]?.boolValue,
            credentialMgmtPreview: map[.textString("credentialMgmtPreview")]?.boolValue
        )
    }
}
