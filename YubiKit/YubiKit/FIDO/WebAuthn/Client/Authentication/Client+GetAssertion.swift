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

    /// Get all matching credentials for selection UI.
    ///
    /// Returns matched credentials that can be inspected for selection UI.
    /// Call `select()` on the chosen credential to complete extension processing.
    /// On success, the returned array is guaranteed to be non-empty. If no matching
    /// credentials exist, throws ``WebAuthn/ClientError/noCredentials(source:)``.
    ///
    /// Uses the client's origin and validates the RP ID.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]> {
        let rpId = options.rpId ?? origin.host
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.get",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await getAssertion(options, clientData: clientData)
    }

    /// Get all matching credentials using custom client data.
    ///
    /// On success, the returned array is guaranteed to be non-empty. If no matching
    /// credentials exist, throws ``WebAuthn/ClientError/noCredentials(source:)``.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.ClientError) {
                    let matches = try await self.performGetAssertions(
                        options: options,
                        clientData: clientData,
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

    // Executes the CTAP2 getAssertion flow with PIN/UV handling and retry logic.
    // For allow-list requests, silently probes to find a matching credential.
    // Throws noCredentials if none exist (after user presence to prevent timing leaks).
    // For discoverable requests, collects all matching assertions from the authenticator.
    fileprivate func performGetAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]>.Continuation
    ) async throws(WebAuthn.ClientError) -> [WebAuthn.Authentication.MatchedCredential] {

        let rpId = clientData.rpId
        let clientDataHash = clientData.clientDataHash

        let requestPIN: @Sendable () async -> String? = {
            await self.awaitPINEntry(from: continuation)
        }
        let requestUVApproval: @Sendable () async -> Bool = {
            await self.awaitUVDecision(from: continuation)
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
                requestPIN: requestPIN,
                requestUVApproval: requestUVApproval
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
                    // Send dummy credential to force UP before revealing no match
                    selectedCred = WebAuthn.CredentialDescriptor(
                        type: options.allowCredentials.first?.type ?? "public-key",
                        id: Data([0x00])
                    )
                }
            }

            let (ctapExtensions, prf, previewSign, largeBlobAction) = try await backend.buildGetAssertionExtensions(
                options.extensions,
                allowCredentials: options.allowCredentials,
                selectedCredentialId: selectedCred?.id
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
                guard retry.shouldRetry(for: error) else { throw WebAuthn.ClientError(error) }
                continue
            }

            var matches: [WebAuthn.Authentication.MatchedCredential] = []
            for ctapResponse in collected {
                matches.append(
                    try buildMatchedCredential(
                        from: ctapResponse,
                        fallbackCredentialId: selectedCred?.id,
                        prf: prf,
                        previewSign: previewSign,
                        largeBlobAction: largeBlobAction,
                        clientData: clientData,
                        token: auth.token
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
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]>.Continuation
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

    // Builds a MatchedCredential from a CTAP response with deferred extension processing.
    fileprivate func buildMatchedCredential(
        from ctapResponse: CTAP2.GetAssertion.Response,
        fallbackCredentialId: Data?,
        prf: WebAuthn.Extension.PRF?,
        previewSign: CTAP2.Extension.PreviewSign?,
        largeBlobAction: WebAuthn.Extension.LargeBlob.Authentication.Input?,
        clientData: WebAuthn.ClientData,
        token: CTAP2.Token?
    ) throws(WebAuthn.ClientError) -> WebAuthn.Authentication.MatchedCredential {
        guard let credentialId = ctapResponse.credential?.id ?? fallbackCredentialId else {
            throw WebAuthn.ClientError(
                CTAP2.SessionError.responseParseError(
                    "Missing credential ID in assertion response",
                    source: .here()
                )
            )
        }

        let backend = self.backend

        return WebAuthn.Authentication.MatchedCredential(
            id: credentialId,
            user: ctapResponse.user,
            select: {
                [ctapResponse, prf, previewSign, largeBlobAction, clientData]
                () async throws(WebAuthn.ClientError) in
                let largeBlobOutput = try await backend.processLargeBlob(
                    from: ctapResponse,
                    action: largeBlobAction,
                    token: token
                )
                let extensionOutputs = try await backend.parseAuthenticationOutputs(
                    from: ctapResponse,
                    prf: prf,
                    previewSign: previewSign,
                    largeBlobOutput: largeBlobOutput
                )
                let authenticatorData = ctapResponse.authenticatorData
                return WebAuthn.Authentication.Response(
                    credentialId: credentialId,
                    rawAuthenticatorData: authenticatorData.rawData,
                    signature: ctapResponse.signature,
                    user: ctapResponse.user,
                    clientExtensionResults: extensionOutputs,
                    signCount: authenticatorData.signCount,
                    authenticatorData: authenticatorData,
                    clientDataJSON: clientData.clientDataJSON
                )
            }
        )
    }
}
