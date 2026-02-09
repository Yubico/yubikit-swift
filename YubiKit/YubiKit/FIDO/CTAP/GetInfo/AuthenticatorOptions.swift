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
    /// Authenticator options indicating capabilities and current configuration.
    ///
    /// Options are either **tri-state** (nil/false/true) or **binary** (false/true):
    /// - **Tri-state**: nil = not supported, false = supported but disabled, true = enabled
    /// - **Binary**: false = not supported, true = supported
    ///
    /// Use `supports*` properties to check tri-state feature support (immutable).
    /// Access properties directly to read current state (may be mutable).
    public struct Options: Sendable, Equatable {

        private let values: [String: Bool]

        /// Access any option by its CTAP string key.
        public subscript(key: String) -> Bool? {
            values[key]
        }

        // MARK: - Immutable Options

        /// Platform authenticator (true) vs roaming authenticator (false).
        public let platformDevice: Bool

        /// Supports resident keys (discoverable credentials).
        public let residentKey: Bool

        /// Capable of testing user presence.
        public let userPresence: Bool

        // MARK: - Tri-State Options

        /// Client PIN status: true = set, false = supported but not set, nil = not supported.
        public let clientPin: Bool?

        /// Built-in user verification status: true = configured, false = supported but not configured, nil = not supported.
        public let userVerification: Bool?

        /// Enterprise attestation status: true = enabled, false = disabled, nil = not supported.
        public let enterpriseAttestation: Bool?

        /// Biometric enrollment status: true = enrolled, false = supported but not enrolled, nil = not supported.
        public let bioEnroll: Bool?

        /// Always require UV: true = enabled, false = disabled, nil = not supported.
        public let alwaysUV: Bool?

        /// Prototype bio enrollment status (FIDO_2_1_PRE): true = enrolled, false = supported but not enrolled, nil = not supported.
        public let userVerificationMgmtPreview: Bool?

        // MARK: - Binary Options

        /// Supports PIN/UV auth token with permissions (CTAP 2.1+). When false or absent, only legacy getPinToken is available.
        public var pinUVAuthToken: Bool? { self["pinUvAuthToken"] }

        /// PIN tokens cannot be used for MakeCredential/GetAssertion.
        public var noMcGaPermissionsWithClientPin: Bool? { self["noMcGaPermissionsWithClientPin"] }

        /// Supports `authenticatorLargeBlobs` command.
        public var largeBlobs: Bool? { self["largeBlobs"] }

        /// Supports requesting `be` (bioEnroll) permission via UV.
        public var uvBioEnroll: Bool? { self["uvBioEnroll"] }

        /// Supports `authenticatorConfig` command.
        public var authenticatorConfig: Bool? { self["authnrCfg"] }

        /// Supports requesting `acfg` (authenticatorConfig) permission via UV.
        public var uvAuthenticatorConfig: Bool? { self["uvAcfg"] }

        /// Supports `authenticatorCredentialManagement` command.
        public var credentialManagement: Bool? { self["credMgmt"] }

        /// Supports `setMinPINLength` subcommand.
        public var setMinPINLength: Bool? { self["setMinPINLength"] }

        /// Allows creating non-discoverable credentials without UV if requested by platform.
        public var makeCredUVNotRequired: Bool? { self["makeCredUvNotRqd"] }

        /// Supports read-only credential management with persistent token (CTAP 2.2).
        public var perCredMgmtRO: Bool? { self["perCredMgmtRO"] }

        /// Supports credential management preview (FIDO_2_1_PRE).
        public var credentialMgmtPreview: Bool? { self["credentialMgmtPreview"] }
    }
}

// MARK: - Tri-State Support Checking

extension CTAP2.GetInfo.Options {
    /// Protocol for checking tri-state option support.
    public protocol SupportChecking {
        var supportsClientPin: Bool { get }
        var supportsUserVerification: Bool { get }
        var supportsEnterpriseAttestation: Bool { get }
        var supportsBioEnroll: Bool { get }
        var supportsAlwaysUV: Bool { get }
        var supportsUserVerificationMgmtPreview: Bool { get }
    }
}

extension CTAP2.GetInfo.Options: CTAP2.GetInfo.Options.SupportChecking {
    public var supportsClientPin: Bool { clientPin != nil }
    public var supportsUserVerification: Bool { userVerification != nil }
    public var supportsEnterpriseAttestation: Bool { enterpriseAttestation != nil }
    public var supportsBioEnroll: Bool { bioEnroll != nil }
    public var supportsAlwaysUV: Bool { alwaysUV != nil }
    public var supportsUserVerificationMgmtPreview: Bool { userVerificationMgmtPreview != nil }
}

// MARK: - CBOR Decoding

extension CTAP2.GetInfo.Options: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let values: [String: Bool] = cbor.cborDecoded() else { return nil }
        self.values = values

        // Immutable
        self.platformDevice = values["plat"] ?? false
        self.residentKey = values["rk"] ?? false
        self.userPresence = values["up"] ?? true

        // Tri-state
        self.clientPin = values["clientPin"]
        self.userVerification = values["uv"]
        self.enterpriseAttestation = values["ep"]
        self.bioEnroll = values["bioEnroll"]
        self.alwaysUV = values["alwaysUv"]
        self.userVerificationMgmtPreview = values["userVerificationMgmtPreview"]
    }
}
