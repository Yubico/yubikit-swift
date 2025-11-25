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
    /// ClientPIN subcommand codes.
    ///
    /// - SeeAlso: [CTAP2.3 authenticatorClientPIN](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorClientPIN)
    enum Subcommand: Int, Sendable {
        /// Get the number of PIN retries remaining.
        case getPinRetries = 0x01

        /// Get the authenticator's public key for key agreement.
        case getKeyAgreement = 0x02

        /// Set a new PIN (authenticator must not have a PIN set).
        case setPIN = 0x03

        /// Change the existing PIN.
        case changePIN = 0x04

        /// Get a PIN token using PIN protocol version 1.
        case getPinToken = 0x05

        /// Get a PIN/UV auth token using UV (biometric/fingerprint).
        ///
        /// This subcommand requires user verification without PIN entry.
        case getPinUvAuthTokenUsingUvWithPermissions = 0x06

        /// Get the number of UV (user verification) retries remaining.
        case getUVRetries = 0x07

        /// Get a PIN/UV auth token using PIN with specific permissions (protocol v2).
        case getPinUvAuthTokenUsingPinWithPermissions = 0x09
    }
}
