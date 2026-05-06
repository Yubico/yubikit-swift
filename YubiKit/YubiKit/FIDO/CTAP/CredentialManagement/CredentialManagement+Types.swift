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

// MARK: - Public Types

extension CTAP2.CredentialManagement {

    /// Metadata about stored credentials on the authenticator.
    public struct Metadata: Sendable {
        /// Total number of discoverable credentials currently stored.
        public let existingCredentialsCount: UInt

        /// Maximum number of additional discoverable credentials that can be stored.
        ///
        /// This is an estimate as actual space depends on algorithm choice,
        /// user entity information size, etc.
        public let maxRemainingCredentialsCount: UInt

        internal init(existingCredentialsCount: UInt, maxRemainingCredentialsCount: UInt) {
            self.existingCredentialsCount = existingCredentialsCount
            self.maxRemainingCredentialsCount = maxRemainingCredentialsCount
        }
    }

    /// Information about a relying party with stored credentials.
    public struct RPData: Sendable {
        /// The relying party entity.
        public let rp: WebAuthn.RelyingParty

        /// SHA-256 hash of the RP ID.
        public let rpIdHash: Data

        internal init(rp: WebAuthn.RelyingParty, rpIdHash: Data) {
            self.rp = rp
            self.rpIdHash = rpIdHash
        }
    }

    /// Information about a stored credential.
    public struct CredentialData: Sendable {
        /// The user entity associated with this credential.
        public let user: WebAuthn.User

        /// The credential identifier.
        public let credentialId: WebAuthn.CredentialDescriptor

        /// The credential's public key.
        public let publicKey: COSE.Key

        /// Credential protection level, if set.
        public let credProtect: CTAP2.Extension.CredProtect.Level?

        /// Large blob key for this credential, if available.
        ///
        /// This is a 32-byte key that can be used to encrypt/decrypt
        /// data in the authenticator's large blob storage.
        public let largeBlobKey: Data?

        /// Whether this credential supports third-party payment.
        public let thirdPartyPayment: Bool?

        internal init(
            user: WebAuthn.User,
            credentialId: WebAuthn.CredentialDescriptor,
            publicKey: COSE.Key,
            credProtect: CTAP2.Extension.CredProtect.Level?,
            largeBlobKey: Data?,
            thirdPartyPayment: Bool?
        ) {
            self.user = user
            self.credentialId = credentialId
            self.publicKey = publicKey
            self.credProtect = credProtect
            self.largeBlobKey = largeBlobKey
            self.thirdPartyPayment = thirdPartyPayment
        }
    }
}

// MARK: - Internal Response Types

extension CTAP2.CredentialManagement {
    /// Internal response from enumerateRPsBegin/enumerateRPsGetNextRP
    struct EnumerateRPsResponse: Sendable {
        let rpData: RPData
        let totalRPs: UInt?
    }

    /// Internal response from enumerateCredentialsBegin/enumerateCredentialsGetNextCredential
    struct EnumerateCredentialsResponse: Sendable {
        let credentialData: CredentialData
        let totalCredentials: UInt?
    }
}
