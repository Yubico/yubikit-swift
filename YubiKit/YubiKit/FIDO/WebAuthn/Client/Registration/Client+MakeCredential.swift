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

// MARK: - Credential Registration

extension WebAuthn.Client {

    // MARK: - Public API

    /// Create a new passkey credential.
    ///
    /// Uses the client's origin and validates the RP ID. PIN/UV is supplied
    /// via the ``WebAuthn/Authorization`` parameter; the SDK invokes its
    /// `providePIN` closure when a PIN is needed. PIN attempts are one-shot:
    /// a wrong PIN throws ``WebAuthn/ClientError/pinRejected(retriesRemaining:source:)``
    /// and the caller re-invokes with a fresh ``WebAuthn/Authorization``.
    ///
    /// - Parameters:
    ///   - options: WebAuthn registration options.
    ///   - authorization: PIN/UV policy for this ceremony. Use
    ///     ``WebAuthn/Authorization/pin(_:)`` for the trivial pre-supplied
    ///     case, ``WebAuthn/Authorization/uvOnly`` for biometric-only, or
    ///     build a custom instance to bridge into a UI.
    public func makeCredential(
        _ options: WebAuthn.Registration.Options,
        authorization: WebAuthn.Authorization
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        let rpId = options.rp.id
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.create",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await makeCredential(
            options,
            clientData: clientData,
            authorization: authorization
        )
    }

    /// Create a new passkey credential with custom client data.
    ///
    /// See ``makeCredential(_:authorization:)`` for `authorization` semantics.
    public func makeCredential(
        _ options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return await backend.makeCredential(
            options: options,
            clientData: clientData,
            authorization: authorization,
            enterpriseRpIds: enterpriseRpIds,
            allowedExtensions: allowedExtensions
        )
    }
}
