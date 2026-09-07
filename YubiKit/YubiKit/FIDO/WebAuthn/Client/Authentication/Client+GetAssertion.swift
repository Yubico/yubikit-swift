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

// MARK: - Credential Authentication

extension WebAuthn.Client {

    // MARK: - Public API

    /// Get matching assertion responses.
    ///
    /// Returns fully-resolved ``Response`` values — extension outputs are
    /// processed eagerly, so selection is purely local. Discoverable-credential
    /// requests return one ``Response`` per match; allow-list requests narrow
    /// to one. Throws ``WebAuthn/ClientError/noCredentials(source:)`` if no
    /// matches exist.
    ///
    /// Uses the client's origin and validates the RP ID. PIN/UV is supplied
    /// via the ``WebAuthn/Authorization`` parameter.
    ///
    /// - Parameters:
    ///   - options: WebAuthn authentication options.
    ///   - authorization: PIN/UV policy for this ceremony. Use
    ///     ``WebAuthn/Authorization/pin(_:)`` for the trivial pre-supplied
    ///     case, ``WebAuthn/Authorization/uvOnly`` for biometric-only, or
    ///     build a custom instance to bridge into a UI.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        authorization: WebAuthn.Authorization
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        let rpId = options.rpId ?? origin.host
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.get",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await getAssertion(
            options,
            clientData: clientData,
            authorization: authorization
        )
    }

    /// Get all matching credentials using custom client data.
    ///
    /// On success, the returned array is guaranteed to be non-empty. If no matching
    /// credentials exist, throws ``WebAuthn/ClientError/noCredentials(source:)``.
    ///
    /// See ``getAssertion(_:authorization:)`` for `authorization` semantics.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return await backend.getAssertions(
            options: options,
            clientData: clientData,
            authorization: authorization,
            allowedExtensions: allowedExtensions
        )
    }
}
