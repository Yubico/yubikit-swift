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

// MARK: - GetRetries Parameters

extension CTAP2.ClientPIN.GetRetries {
    /// Parameters for getPinRetries.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = CTAP2.ClientPIN.GetRetries.Response
        static let commandCode = CTAP2.ClientPIN.GetRetries.commandCode

        init() {}
    }
}

// MARK: - GetKeyAgreement Parameters

extension CTAP2.ClientPIN.GetKeyAgreement {
    /// Parameters for getKeyAgreement.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = CTAP2.ClientPIN.GetKeyAgreement.Response
        static let commandCode = CTAP2.ClientPIN.GetKeyAgreement.commandCode

        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        init(pinUvAuthProtocol: PinAuth.Version) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
        }
    }
}

// MARK: - SetPIN Parameters

extension CTAP2.ClientPIN.SetPIN {
    /// Parameters for setPIN.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = Void
        static let commandCode = CTAP2.ClientPIN.SetPIN.commandCode

        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// New PIN encrypted with shared secret, padded to 64 bytes.
        let newPinEnc: Data

        /// HMAC of newPinEnc using shared secret.
        let pinUvAuthParam: Data

        init(
            pinUvAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            newPinEnc: Data,
            pinUvAuthParam: Data
        ) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.keyAgreement = keyAgreement
            self.newPinEnc = newPinEnc
            self.pinUvAuthParam = pinUvAuthParam
        }
    }
}

// MARK: - ChangePIN Parameters

extension CTAP2.ClientPIN.ChangePIN {
    /// Parameters for changePIN.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = Void
        static let commandCode = CTAP2.ClientPIN.ChangePIN.commandCode

        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// New PIN encrypted with shared secret, padded to 64 bytes.
        let newPinEnc: Data

        /// Current PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        /// HMAC of (newPinEnc || pinHashEnc) using shared secret.
        let pinUvAuthParam: Data

        init(
            pinUvAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            newPinEnc: Data,
            pinHashEnc: Data,
            pinUvAuthParam: Data
        ) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.keyAgreement = keyAgreement
            self.newPinEnc = newPinEnc
            self.pinHashEnc = pinHashEnc
            self.pinUvAuthParam = pinUvAuthParam
        }
    }
}

// MARK: - GetToken Parameters

extension CTAP2.ClientPIN.GetToken {
    /// Parameters for getPinToken.
    ///
    /// Gets a PIN token using PIN. Superseded by `GetTokenWithPermissions` in CTAP 2.1+.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = CTAP2.ClientPIN.GetToken.Response
        static let commandCode = CTAP2.ClientPIN.GetToken.commandCode

        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        init(
            pinUvAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            pinHashEnc: Data
        ) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.keyAgreement = keyAgreement
            self.pinHashEnc = pinHashEnc
        }
    }
}

// MARK: - GetUvRetries Parameters

extension CTAP2.ClientPIN.GetUvRetries {
    /// Parameters for getUVRetries.
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = CTAP2.ClientPIN.GetUvRetries.Response
        static let commandCode = CTAP2.ClientPIN.GetUvRetries.commandCode

        init() {}
    }
}

// MARK: - GetTokenWithPermissions Parameters

extension CTAP2.ClientPIN.GetTokenWithPermissions {
    /// Parameters for getPinUvAuthTokenUsingPinWithPermissions.
    ///
    /// Gets a PIN/UV auth token using PIN with specific permissions (CTAP 2.1+).
    struct Parameters: CTAP2.ClientPIN.Command {
        typealias Response = CTAP2.ClientPIN.GetToken.Response  // Same response type as GetToken
        static let commandCode = CTAP2.ClientPIN.GetTokenWithPermissions.commandCode

        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        /// Permissions to associate with the token.
        let permissions: CTAP2.ClientPIN.Permission

        /// Relying Party ID (required for mc/ga permissions, optional for cm).
        let rpId: String?

        init(
            pinUvAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            pinHashEnc: Data,
            permissions: CTAP2.ClientPIN.Permission,
            rpId: String? = nil
        ) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.keyAgreement = keyAgreement
            self.pinHashEnc = pinHashEnc
            self.permissions = permissions
            self.rpId = rpId
        }
    }
}
