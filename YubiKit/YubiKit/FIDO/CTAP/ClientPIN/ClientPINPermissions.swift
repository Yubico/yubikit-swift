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
    /// Permissions for PIN/UV auth tokens.
    ///
    /// These permissions scope what operations can be performed with a PIN token.
    /// Protocol v2 (CTAP 2.1+) requires permissions to be specified when obtaining tokens.
    ///
    /// - SeeAlso: [CTAP2.3 Section 6.5.5.7](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#getPinUvAuthTokenUsingPinWithPermissions)
    struct Permission: OptionSet, Sendable, CBOR.Encodable {
        let rawValue: UInt8

        /// Permission to create credentials (makeCredential command).
        static let makeCredential = Permission(rawValue: 0x01)

        /// Permission to get assertions (getAssertion command).
        static let getAssertion = Permission(rawValue: 0x02)

        /// Permission to manage credentials (credentialManagement command).
        static let credentialManagement = Permission(rawValue: 0x04)

        /// Permission to enroll biometrics (bioEnrollment command).
        static let bioEnrollment = Permission(rawValue: 0x08)

        /// Permission to write large blobs (largeBlobs write operation).
        static let largeBlobWrite = Permission(rawValue: 0x10)

        /// Permission to configure authenticator (authenticatorConfig command).
        static let authenticatorConfig = Permission(rawValue: 0x20)

        /// Permission for persistent credential management.
        ///
        /// Available on YubiKey firmware 5.7+.
        static let persistentCredentialManagement = Permission(rawValue: 0x40)

        func cbor() -> CBOR.Value {
            rawValue.cbor()
        }
    }
}
