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

extension CTAP2.ClientPin {
    /// Permissions for PIN/UV auth tokens.
    ///
    /// These permissions scope what operations can be performed with a PIN token.
    /// Protocol v2 (CTAP 2.1+) requires permissions to be specified when obtaining tokens.
    ///
    /// - SeeAlso: [CTAP 2.2 Section 6.5.5.7](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#getPinUvAuthTokenUsingPinWithPermissions)
    public struct Permission: OptionSet, Sendable, CBOR.Encodable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Permission to create credentials (makeCredential command).
        public static let makeCredential = Permission(rawValue: 0x01)

        /// Permission to get assertions (getAssertion command).
        public static let getAssertion = Permission(rawValue: 0x02)

        /// Permission to manage credentials (credentialManagement command).
        public static let credentialManagement = Permission(rawValue: 0x04)

        /// Permission to enroll biometrics (bioEnrollment command).
        public static let bioEnrollment = Permission(rawValue: 0x08)

        /// Permission to write large blobs (largeBlobs write operation).
        public static let largeBlobWrite = Permission(rawValue: 0x10)

        /// Permission to configure authenticator (authenticatorConfig command).
        public static let authenticatorConfig = Permission(rawValue: 0x20)

        /// Permission for persistent credential management.
        ///
        /// Available on YubiKey firmware 5.7+.
        public static let persistentCredentialManagement = Permission(rawValue: 0x40)
    }
}
