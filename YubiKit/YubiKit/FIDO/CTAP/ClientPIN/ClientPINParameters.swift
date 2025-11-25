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

extension CTAP2.ClientPIN {
    /// Parameters for the authenticatorClientPIN command.
    ///
    /// - SeeAlso: [CTAP2.3 authenticatorClientPIN](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorClientPIN)
    struct Parameters: Sendable {
        /// PIN/UV auth protocol version.
        let pinUvAuthProtocol: PinAuth.Version

        /// Subcommand to execute.
        let subCommand: Subcommand

        /// Platform's public key for key agreement (COSE_Key format).
        let keyAgreement: COSE.Key?

        /// PIN/UV auth parameter (HMAC output, first 16 bytes).
        let pinUvAuthParam: Data?

        /// New PIN encrypted with shared secret.
        let newPinEnc: Data?

        /// PIN hash encrypted with shared secret.
        let pinHashEnc: Data?

        /// Permissions for getPinUvAuthTokenUsingPinWithPermissions (v2).
        let permissions: Permission?

        /// Relying Party ID for getPinUvAuthTokenUsingPinWithPermissions (v2).
        let rpId: String?

        init(
            pinUvAuthProtocol: PinAuth.Version,
            subCommand: Subcommand,
            keyAgreement: COSE.Key? = nil,
            pinUvAuthParam: Data? = nil,
            newPinEnc: Data? = nil,
            pinHashEnc: Data? = nil,
            permissions: Permission? = nil,
            rpId: String? = nil
        ) {
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.subCommand = subCommand
            self.keyAgreement = keyAgreement
            self.pinUvAuthParam = pinUvAuthParam
            self.newPinEnc = newPinEnc
            self.pinHashEnc = pinHashEnc
            self.permissions = permissions
            self.rpId = rpId
        }
    }
}
