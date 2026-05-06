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
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.ClientError) {
                    let matches = try await self.performGetAssertions(
                        options: options,
                        clientData: clientData,
                        authorization: authorization,
                        continuation: continuation
                    )
                    continuation.yield(.finished(matches))
                } catch {
                    continuation.yield(error: error)
                }
            }
        }.withTimeout(options.timeout)
    }
}

// MARK: - Private Implementation

extension WebAuthn.Client {

    fileprivate func performGetAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.Response]>.Continuation
    ) async throws(WebAuthn.ClientError) -> [WebAuthn.Authentication.Response] {

        let rpId = clientData.rpId
        let clientDataHash = clientData.clientDataHash

        // WebAuthn L3 §10.1.5: largeBlob.write requires exactly one entry in
        // allowCredentials. Without this guard, multi-match assertions fan the
        // write out across every matched credential.
        if case .write = options.extensions?.largeBlob, options.allowCredentials.count != 1 {
            throw .notSupported(
                "largeBlob.write requires allowCredentials to contain exactly one entry",
                source: .here()
            )
        }

        var permissions: CTAP2.ClientPin.Permission = .getAssertion
        if case .write = options.extensions?.largeBlob,
            (try? await backend.isLargeBlobSupported()) == true
        {
            permissions.insert(.largeBlobWrite)
        }

        var retry = RetryContext(userVerification: options.userVerification)

        while true {
            let info: CTAP2.GetInfo.Response
            do throws(CTAP2.SessionError) {
                info = try await backend.getInfo()
            } catch {
                throw WebAuthn.ClientError(error)
            }

            let auth = try await acquireAuthToken(
                info: info,
                permissions: permissions,
                rpId: rpId,
                userVerification: retry.userVerification,
                isMakeCredential: false,
                allowUV: retry.allowUV,
                authorization: authorization,
                yieldProcessing: { continuation.yield(.processing) },
                yieldUVWaiting: { cancel, fallback in
                    continuation.yield(
                        .waitingForUserVerification(cancel: cancel, fallbackToPIN: fallback)
                    )
                }
            )

            // For allow-list requests, silently probe to find a matching credential.
            // If none found, send a dummy credential to ensure user presence is required
            // before revealing "no credentials" - prevents timing side-channel attacks.
            var selectedCred: WebAuthn.CredentialDescriptor?
            if !options.allowCredentials.isEmpty {
                let cachedInfo: CTAP2.GetInfo.ImmutableView
                do throws(CTAP2.SessionError) {
                    cachedInfo = try await backend.cachedInfo
                } catch {
                    throw WebAuthn.ClientError(error)
                }
                selectedCred = try await findMatchingCredential(
                    from: options.allowCredentials,
                    rpId: rpId,
                    cachedInfo: cachedInfo,
                    token: auth.token
                )
                if selectedCred == nil {
                    selectedCred = WebAuthn.CredentialDescriptor(
                        type: options.allowCredentials.first?.type ?? "public-key",
                        id: Data([0x00])
                    )
                }
            }

            let (ctapExtensions, prf, previewSign, largeBlobAction) = try await backend.buildGetAssertionExtensions(
                options.extensions,
                allowCredentials: options.allowCredentials,
                selectedCredentialId: selectedCred?.id,
                allowedExtensions: allowedExtensions
            )

            let parameters = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: selectedCred.map { [.init(id: $0.id)] },
                extensions: ctapExtensions,
                up: true,
                uv: auth.uv
            )

            let collected: [CTAP2.GetAssertion.Response]
            do throws(CTAP2.SessionError) {
                let firstResponse = try await sendAssertion(
                    parameters: parameters,
                    token: auth.token,
                    continuation: continuation
                )

                var allResponses = [firstResponse]
                let total = firstResponse.numberOfCredentials ?? 1
                for _ in 1..<total {
                    allResponses.append(try await backend.getNextAssertion().value)
                }
                collected = allResponses
            } catch {
                if case .ctapError(.noCredentials, _) = error {
                    throw .noCredentials(source: .here())
                }
                guard retry.shouldRetry(for: error) else {
                    if case .ctapError(.uvInvalid, _) = error {
                        throw try await translateUVInvalid()
                    }
                    throw WebAuthn.ClientError(error)
                }
                continue
            }

            var matches: [WebAuthn.Authentication.Response] = []
            matches.reserveCapacity(collected.count)
            for ctapResponse in collected {
                guard let credentialId = ctapResponse.credential?.id ?? selectedCred?.id else {
                    throw WebAuthn.ClientError(
                        CTAP2.SessionError.responseParseError(
                            "Missing credential ID in assertion response",
                            source: .here()
                        )
                    )
                }
                // Resolve extension outputs on the live connection so the
                // returned `Response` is self-contained — selection by the
                // caller is purely local.
                let largeBlobOutput = try await backend.processLargeBlob(
                    from: ctapResponse,
                    action: largeBlobAction,
                    token: auth.token
                )
                let extensionOutputs = try await backend.parseAuthenticationOutputs(
                    from: ctapResponse,
                    prf: prf,
                    previewSign: previewSign,
                    largeBlobOutput: largeBlobOutput,
                    allowedExtensions: allowedExtensions
                )
                let authData = ctapResponse.authenticatorData
                matches.append(
                    WebAuthn.Authentication.Response(
                        credentialId: credentialId,
                        rawAuthenticatorData: authData.rawData,
                        signature: ctapResponse.signature,
                        user: ctapResponse.user,
                        clientExtensionResults: extensionOutputs,
                        signCount: authData.signCount,
                        authenticatorData: authData,
                        clientDataJSON: clientData.clientDataJSON
                    )
                )
            }
            return matches
        }
    }
}

// MARK: - Shared Helpers

extension WebAuthn.Client {

    // Sends a getAssertion command and forwards status updates to the continuation.
    fileprivate func sendAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        token: CTAP2.Token?,
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.Response]>.Continuation
    ) async throws(CTAP2.SessionError) -> CTAP2.GetAssertion.Response {
        let stream = await backend.getAssertion(parameters: parameters, token: token)
        var response: CTAP2.GetAssertion.Response?
        for try await ctapStatus in stream {
            switch ctapStatus {
            case .processing:
                continuation.yield(.processing)
            case .waitingForUser(let cancel):
                continuation.yield(.waitingForUser(cancel: cancel))
            case .finished(let r):
                response = r
            }
        }
        guard let response else {
            throw CTAP2.SessionError.responseParseError(
                "Missing response from getAssertion",
                source: .here()
            )
        }
        return response
    }
}
