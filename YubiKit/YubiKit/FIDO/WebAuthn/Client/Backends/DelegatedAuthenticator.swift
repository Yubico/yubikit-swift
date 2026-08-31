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

// MARK: - Delegated Authenticator

extension WebAuthn {

    /*
     * An authenticator this SDK does not implement, driven in-process rather than over CTAP2.
     *
     * `Client` normally speaks CTAP2 to a YubiKey. A conformer takes its place: the client keeps
     * performing the ceremony — RP ID validation, client data, credential matching, response
     * assembly — and delegates only the operations that need the credentials themselves.
     *
     * This is *not* an external (roaming) authenticator in the WebAuthn sense. A YubiKey is that,
     * and it is `Client.Backend.ctap2`. This is for an authenticator implemented outside YubiKit:
     * a Secure Enclave-backed store, another SDK's key store, a fake in a test.
     *
     * Inputs arrive already resolved by the client — `rpId` validated against the origin,
     * `clientDataHash` hashed — and conformers return raw authenticator output for the client to
     * assemble. Failures are `ClientError` directly, so there is no translation table on either
     * side. Deleting credentials is absent by design: no WebAuthn ceremony removes one.
     */
    @_spi(YubiInternal)
    public protocol DelegatedAuthenticator: Sendable {

        // Attachment modality every response from this authenticator reports. The client cannot
        // infer it: delegation says nothing about where the credentials live. A Secure
        // Enclave-backed store is `.platform`; something roaming reached over a non-CTAP2
        // transport is `.crossPlatform`.
        nonisolated var attachment: AuthenticatorAttachment { get }

        // Creates a credential. Evaluate `excludeCredentialIds` only *after* verifying the user —
        // credential presence must not be revealed to an unverified caller — and throw
        // `.credentialExcluded` on a match.
        //
        // The client does not negotiate the algorithm; it cannot know what a conformer signs with.
        // Pick a supported entry from `pubKeyCredParams` (empty means the client's defaults), or
        // throw `.unsupportedAlgorithm`.
        func makeCredential(
            rpId: String,
            userHandle: Data,
            userName: String?,
            clientDataHash: Data,
            pubKeyCredParams: [COSE.Algorithm],
            excludeCredentialIds: [Data]
        ) async throws(ClientError) -> AuthenticatorRegistration

        // Signs with each selected credential, in the given order, in one user-verification
        // ceremony.
        //
        // An empty `credentialIds` must still verify the user before throwing `.noCredentials`,
        // so a caller cannot learn from timing whether a credential is present — the same reason
        // the CTAP2 path sends a dummy credential.
        func getAssertions(
            credentialIds: [Data],
            rpId: String,
            clientDataHash: Data
        ) async throws(ClientError) -> [AuthenticatorAssertion]

        // Lists stored credentials. The client always scopes to one relying party; listing must
        // not reveal credentials belonging to another.
        func listCredentials(rpId: String?) async throws(ClientError) -> [AuthenticatorCredential]
    }

    // MARK: - Authenticator Output

    // Only the authenticator data: everything a `Registration.Response` reports — credential id,
    // public key, AAGUID, sign count — is inside its attested credential data, and the client
    // parses it there rather than trusting a conformer to repeat itself consistently.
    @_spi(YubiInternal)
    public struct AuthenticatorRegistration: Sendable, Hashable {

        // Raw authenticator data. The AT flag must be set and attested credential data present.
        public let authenticatorData: Data

        // Whether the new credential is discoverable, reported as `credProps.rk` when the relying
        // party asked for it. Only the authenticator knows: the request carries a preference, not
        // an outcome.
        public let isDiscoverable: Bool

        public init(authenticatorData: Data, isDiscoverable: Bool) {
            self.authenticatorData = authenticatorData
            self.isDiscoverable = isDiscoverable
        }
    }

    @_spi(YubiInternal)
    public struct AuthenticatorAssertion: Sendable, Hashable {

        public let credentialId: Data

        // An empty handle is not the same as no handle; pass `nil` when there is none.
        public let userHandle: Data?

        // Over `authenticatorData || clientDataHash`.
        public let signature: Data

        public let authenticatorData: Data

        public init(credentialId: Data, userHandle: Data?, signature: Data, authenticatorData: Data) {
            self.credentialId = credentialId
            self.userHandle = userHandle
            self.signature = signature
            self.authenticatorData = authenticatorData
        }
    }

    @_spi(YubiInternal)
    public struct AuthenticatorCredential: Sendable, Hashable {

        public let id: Data
        public let rpId: String

        // For presenting a choice to the user.
        public let userName: String?

        public init(id: Data, rpId: String, userName: String?) {
            self.id = id
            self.rpId = rpId
            self.userName = userName
        }
    }
}
