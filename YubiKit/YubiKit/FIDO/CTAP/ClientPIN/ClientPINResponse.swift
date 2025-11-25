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
    /// Response from the authenticatorClientPIN command.
    ///
    /// Different subcommands return different fields.
    ///
    /// - SeeAlso: [CTAP2.3 authenticatorClientPIN Response](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorClientPIN)
    struct Response: Sendable {
        /// Authenticator's public key for key agreement (COSE_Key format).
        ///
        /// Returned by: getKeyAgreement
        let keyAgreement: COSE.Key?

        /// Encrypted PIN token.
        ///
        /// Returned by: getPinToken, getPinUvAuthTokenUsingPinWithPermissions
        let pinUvAuthToken: Data?

        /// Number of PIN retries remaining.
        ///
        /// Returned by: getPinRetries
        let pinRetries: Int?

        /// Power cycle state (true if power cycle required).
        ///
        /// Returned by: getPinRetries (when PIN auth is blocked)
        let powerCycleState: Bool?

        /// Number of UV (user verification) retries remaining.
        ///
        /// Returned by: getUVRetries
        let uvRetries: Int?

        init(
            keyAgreement: COSE.Key? = nil,
            pinUvAuthToken: Data? = nil,
            pinRetries: Int? = nil,
            powerCycleState: Bool? = nil,
            uvRetries: Int? = nil
        ) {
            self.keyAgreement = keyAgreement
            self.pinUvAuthToken = pinUvAuthToken
            self.pinRetries = pinRetries
            self.powerCycleState = powerCycleState
            self.uvRetries = uvRetries
        }
    }
}
