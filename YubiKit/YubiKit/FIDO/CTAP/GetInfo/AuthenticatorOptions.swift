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
    ///
    /// Use the typed properties for known options, or the subscript for custom/unknown options:
    /// ```swift
    /// let pinSet = options.clientPin      // Typed access
    /// let custom = options["customOption"] // String subscript
    /// ```
    public struct Options: Sendable, Equatable {

        private let values: [String: Bool]

        /// Access any option by its CTAP string key.
        ///
        /// Returns `nil` if the option is not present in the authenticator's response.
        public subscript(key: String) -> Bool? {
            values[key]
        }

        // MARK: - CTAP 2.0 Options

        /// Indicates the device is attached to the client and cannot be removed.
        ///
        /// If `true`, the authenticator is a platform authenticator (built into the client device).
        /// If `false` or absent, it's a roaming authenticator.
        public var platformDevice: Bool { self["plat"] ?? false }

        /// Indicates the device supports resident keys (discoverable credentials).
        ///
        /// If `true`, the authenticator can store credentials on-device.
        public var residentKey: Bool { self["rk"] ?? false }

        /// Indicates the device is capable of testing user presence.
        ///
        /// Defaults to `true` if absent.
        public var userPresence: Bool { self["up"] ?? true }

        /// Client PIN support status.
        ///
        /// - `true`: PIN is supported and has been set
        /// - `false`: PIN is supported but not yet set
        /// - `nil`: PIN is not supported
        public var clientPin: Bool? { self["clientPin"] }

        /// Built-in user verification support status.
        ///
        /// - `true`: UV is supported and configured (e.g., biometric enrolled)
        /// - `false`: UV is supported but not yet configured
        /// - `nil`: UV is not supported (device can only do Client PIN)
        public var userVerification: Bool? { self["uv"] }

        // MARK: - CTAP 2.1 Options

        /// Indicates support for `getPinUVAuthTokenUsingPinWithPermissions` and
        /// `getPinUVAuthTokenUsingUVWithPermissions` subcommands.
        ///
        /// When `true`:
        /// - If `clientPin` is `true`, supports `getPinUVAuthTokenUsingPinWithPermissions`
        /// - If `userVerification` is `true`, supports `getPinUVAuthTokenUsingUVWithPermissions`
        ///
        /// When `false` or absent, only legacy `getPinToken` is supported.
        public var pinUVAuthToken: Bool? { self["pinUvAuthToken"] }

        /// Indicates that tokens obtained via PIN cannot be used for MakeCredential/GetAssertion.
        ///
        /// When `true`, platforms should not attempt `getPinUVAuthTokenUsingPinWithPermissions`
        /// if `getPinUVAuthTokenUsingUVWithPermissions` fails.
        public var noMcGaPermissionsWithClientPin: Bool? { self["noMcGaPermissionsWithClientPin"] }

        /// Indicates support for the `authenticatorLargeBlobs` command.
        public var largeBlobs: Bool? { self["largeBlobs"] }

        /// Enterprise Attestation support status.
        ///
        /// - `true`: Supported and enabled
        /// - `false`: Supported but disabled
        /// - `nil`: Not supported
        public var enterpriseAttestation: Bool? { self["ep"] }

        /// Biometric enrollment support status.
        ///
        /// - `true`: Supported with at least one enrollment provisioned
        /// - `false`: Supported but no enrollments yet
        /// - `nil`: Not supported
        public var bioEnroll: Bool? { self["bioEnroll"] }

        /// Indicates support for requesting `be` permission via UV.
        ///
        /// Only present if `bioEnroll` is also present.
        public var uvBioEnroll: Bool? { self["uvBioEnroll"] }

        /// Indicates support for the `authenticatorConfig` command.
        public var authenticatorConfig: Bool? { self["authnrCfg"] }

        /// Indicates support for requesting `acfg` permission via UV.
        ///
        /// Only present if `authenticatorConfig` is also present.
        public var uvAuthenticatorConfig: Bool? { self["uvAcfg"] }

        /// Indicates support for the `authenticatorCredentialManagement` command.
        public var credentialManagement: Bool? { self["credMgmt"] }

        /// Indicates support for the `setMinPINLength` subcommand.
        ///
        /// Only present if `clientPin` is also present.
        public var setMinPINLength: Bool? { self["setMinPINLength"] }

        /// Indicates non-discoverable credentials can be created without user verification.
        ///
        /// When `true`, the authenticator allows creating non-discoverable credentials
        /// without requiring any form of user verification if the platform requests it.
        public var makeCredUVNotRequired: Bool? { self["makeCredUvNotRqd"] }

        /// Always Require User Verification feature status.
        ///
        /// - `true`: Supported and enabled
        /// - `false`: Supported but disabled
        /// - `nil`: Not supported
        ///
        /// If `true`, `makeCredUVNotRequired` must be `false`.
        public var alwaysUV: Bool? { self["alwaysUv"] }

        // MARK: - Preview/Prototype Options

        /// Prototype biometric enrollment support (FIDO_2_1_PRE).
        public var userVerificationMgmtPreview: Bool? { self["userVerificationMgmtPreview"] }

        /// Prototype credential management support (FIDO_2_1_PRE).
        public var credentialMgmtPreview: Bool? { self["credentialMgmtPreview"] }
    }
}

// MARK: - CBOR Decoding

extension CTAP2.GetInfo.Options: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let values: [String: Bool] = cbor.cborDecoded() else { return nil }
        self.values = values
    }
}
