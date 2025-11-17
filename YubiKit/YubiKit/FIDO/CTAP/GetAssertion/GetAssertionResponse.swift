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

extension CTAP.GetAssertion {
    /// Response from the authenticatorGetAssertion command.
    ///
    /// Contains the authentication assertion including signature and authenticator data.
    ///
    /// - SeeAlso: [CTAP2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorGetAssertion)
    struct Response: Sendable {
        /// The credential that was used to generate this assertion.
        /// Only present when multiple credentials match or when using resident keys.
        let credential: PublicKeyCredentialDescriptor?

        /// Authenticator data for this assertion.
        let authenticatorData: WebAuthn.AuthenticatorData

        /// Signature over authenticatorData and clientDataHash.
        let signature: Data

        /// User information associated with this credential.
        /// Only present when the credential is a resident key.
        let user: PublicKeyCredentialUserEntity?

        /// Total number of credentials available for this RP.
        /// When present and > 1, use getNextAssertion to retrieve additional assertions.
        let numberOfCredentials: Int?

        /// Indicates if the user explicitly selected this credential (CTAP 2.2+).
        /// When true, the authenticator presented multiple credentials and the user selected this one.
        let userSelected: Bool?

        /// Large blob key associated with this credential (CTAP 2.1+).
        let largeBlobKey: Data?

        init(
            credential: PublicKeyCredentialDescriptor? = nil,
            authenticatorData: WebAuthn.AuthenticatorData,
            signature: Data,
            user: PublicKeyCredentialUserEntity? = nil,
            numberOfCredentials: Int? = nil,
            userSelected: Bool? = nil,
            largeBlobKey: Data? = nil
        ) {
            self.credential = credential
            self.authenticatorData = authenticatorData
            self.signature = signature
            self.user = user
            self.numberOfCredentials = numberOfCredentials
            self.userSelected = userSelected
            self.largeBlobKey = largeBlobKey
        }
    }
}
