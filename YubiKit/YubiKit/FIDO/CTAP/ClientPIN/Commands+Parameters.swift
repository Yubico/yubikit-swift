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

extension CTAP2.ClientPin.GetRetries {
    /// Parameters for getPinRetries.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = CTAP2.ClientPin.GetRetries.Response
        static let commandCode = CTAP2.ClientPin.GetRetries.commandCode

        init() {}
    }
}

// MARK: - GetKeyAgreement Parameters

extension CTAP2.ClientPin.GetKeyAgreement {
    /// Parameters for getKeyAgreement.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = CTAP2.ClientPin.GetKeyAgreement.Response
        static let commandCode = CTAP2.ClientPin.GetKeyAgreement.commandCode

        /// PIN/UV auth protocol version.
        let pinUVAuthProtocol: PinAuth.Version

        init(pinUVAuthProtocol: PinAuth.Version) {
            self.pinUVAuthProtocol = pinUVAuthProtocol
        }
    }
}

// MARK: - SetPIN Parameters

extension CTAP2.ClientPin.SetPin {
    /// Parameters for setPIN.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = Void
        static let commandCode = CTAP2.ClientPin.SetPin.commandCode

        /// PIN/UV auth protocol version.
        let pinUVAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// New PIN encrypted with shared secret, padded to 64 bytes.
        let newPinEnc: Data

        /// HMAC of newPinEnc using shared secret.
        let pinUVAuthParam: Data

        init(
            pinUVAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            newPinEnc: Data,
            pinUVAuthParam: Data
        ) {
            self.pinUVAuthProtocol = pinUVAuthProtocol
            self.keyAgreement = keyAgreement
            self.newPinEnc = newPinEnc
            self.pinUVAuthParam = pinUVAuthParam
        }
    }
}

// MARK: - ChangePIN Parameters

extension CTAP2.ClientPin.ChangePin {
    /// Parameters for changePIN.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = Void
        static let commandCode = CTAP2.ClientPin.ChangePin.commandCode

        /// PIN/UV auth protocol version.
        let pinUVAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// New PIN encrypted with shared secret, padded to 64 bytes.
        let newPinEnc: Data

        /// Current PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        /// HMAC of (newPinEnc || pinHashEnc) using shared secret.
        let pinUVAuthParam: Data

        init(
            pinUVAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            newPinEnc: Data,
            pinHashEnc: Data,
            pinUVAuthParam: Data
        ) {
            self.pinUVAuthProtocol = pinUVAuthProtocol
            self.keyAgreement = keyAgreement
            self.newPinEnc = newPinEnc
            self.pinHashEnc = pinHashEnc
            self.pinUVAuthParam = pinUVAuthParam
        }
    }
}

// MARK: - GetToken Parameters

extension CTAP2.ClientPin.GetToken {
    /// Parameters for getPinToken.
    ///
    /// Gets a PIN token using PIN. Superseded by `GetTokenWithPermissions` in CTAP 2.1+.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = CTAP2.ClientPin.GetToken.Response
        static let commandCode = CTAP2.ClientPin.GetToken.commandCode

        /// PIN/UV auth protocol version.
        let pinUVAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        init(
            pinUVAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            pinHashEnc: Data
        ) {
            self.pinUVAuthProtocol = pinUVAuthProtocol
            self.keyAgreement = keyAgreement
            self.pinHashEnc = pinHashEnc
        }
    }
}

// MARK: - GetUVRetries Parameters

extension CTAP2.ClientPin.GetUVRetries {
    /// Parameters for getUVRetries.
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = CTAP2.ClientPin.GetUVRetries.Response
        static let commandCode = CTAP2.ClientPin.GetUVRetries.commandCode

        init() {}
    }
}

// MARK: - GetTokenWithPermissions Parameters

extension CTAP2.ClientPin.GetTokenWithPermissions {
    /// Parameters for getPinUvAuthTokenUsingPinWithPermissions.
    ///
    /// Gets a PIN/UV auth token using PIN with specific permissions (CTAP 2.1+).
    struct Parameters: CTAP2.ClientPin.Command {
        typealias Response = CTAP2.ClientPin.GetToken.Response  // Same response type as GetToken
        static let commandCode = CTAP2.ClientPin.GetTokenWithPermissions.commandCode

        /// PIN/UV auth protocol version.
        let pinUVAuthProtocol: PinAuth.Version

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key

        /// PIN hash (first 16 bytes of SHA-256) encrypted with shared secret.
        let pinHashEnc: Data

        /// Permissions to associate with the token.
        let permissions: CTAP2.ClientPin.Permission

        /// Relying Party ID (required for mc/ga permissions, optional for cm).
        let rpId: String?

        init(
            pinUVAuthProtocol: PinAuth.Version,
            keyAgreement: COSE.Key,
            pinHashEnc: Data,
            permissions: CTAP2.ClientPin.Permission,
            rpId: String? = nil
        ) {
            self.pinUVAuthProtocol = pinUVAuthProtocol
            self.keyAgreement = keyAgreement
            self.pinHashEnc = pinHashEnc
            self.permissions = permissions
            self.rpId = rpId
        }
    }
}
