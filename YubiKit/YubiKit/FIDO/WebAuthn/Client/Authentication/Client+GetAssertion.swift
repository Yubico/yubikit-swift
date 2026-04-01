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

    /// Authenticate with an existing passkey credential.
    ///
    /// Uses the client's origin and validates the RP ID.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options
    ) async -> WebAuthn.StatusStream<WebAuthn.Authentication.Response> {
        let rpId = options.rpId ?? origin.host
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.get",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await getAssertion(options, clientData: clientData)
    }

    /// Authenticate with an existing passkey credential using custom client data.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData
    ) async -> WebAuthn.StatusStream<WebAuthn.Authentication.Response> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return await getAssertions(options, clientData: clientData).selectFirst()
    }

    /// Get all matching credentials for selection UI.
    ///
    /// Returns matched credentials that can be inspected for selection UI.
    /// Call `select()` on the chosen credential to complete extension processing.
    ///
    /// Uses the client's origin and validates the RP ID.
    public func getAssertions(
        _ options: WebAuthn.Authentication.Options
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]> {
        let rpId = options.rpId ?? origin.host
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.get",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await getAssertions(options, clientData: clientData)
    }

    /// Get all matching credentials using custom client data.
    public func getAssertions(
        _ options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.Error) {
                    let pendingCredentials = try await performGetAssertions(
                        options: options,
                        clientData: clientData,
                        continuation: continuation
                    )
                    guard !pendingCredentials.isEmpty else {
                        throw WebAuthn.Error.noCredentials(source: .here())
                    }
                    continuation.yield(.finished(pendingCredentials))
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
    // Returns matched credentials with deferred extension processing.
    fileprivate func performGetAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.MatchedCredential]>.Continuation
    ) async throws(WebAuthn.Error) -> [WebAuthn.Authentication.MatchedCredential] {

        let cachedInfo: CTAP2.GetInfo.ImmutableView
        do throws(CTAP2.SessionError) {
            cachedInfo = try await backend.cachedInfo
        } catch {
            throw WebAuthn.Error(error)
        }
        let rpId = clientData.rpId
        let clientDataHash = clientData.clientDataHash

        var retry = RetryContext(userVerification: options.userVerification)

        // Retry loop for recoverable UV/PIN errors.
        while true {
            // Re-fetch mutable state (PIN/UV counters) on each attempt.
            let info: CTAP2.GetInfo.Response
            do throws(CTAP2.SessionError) {
                info = try await backend.getInfo()
            } catch {
                throw WebAuthn.Error(error)
            }

            let requestUVApproval: @Sendable () async -> Bool = {
                await self.awaitUVDecision(from: continuation)
            }

            // Only request largeBlobWrite when supported and a write is requested.
            var permissions: CTAP2.ClientPin.Permission = .getAssertion
            if case .write = options.extensions?.largeBlob,
                (try? await backend.isLargeBlobSupported()) == true
            {
                permissions.insert(.largeBlobWrite)
            }

            let auth = try await acquireAuthToken(
                info: info,
                permissions: permissions,
                rpId: rpId,
                userVerification: retry.userVerification,
                isMakeCredential: false,
                allowUV: retry.allowUV,
                requestUVApproval: requestUVApproval
            )

            // Silently probe allow list to find which credential exists.
            let selectedCred = try await findMatchingCredential(
                from: options.allowCredentials,
                rpId: rpId,
                cachedInfo: cachedInfo,
                token: auth.token
            )

            let allowList = buildAllowList(options.allowCredentials, selectedCred: selectedCred)

            let (ctapExtensions, prf, largeBlobAction) = try await backend.buildGetAssertionExtensions(
                options.extensions,
                allowCredentials: options.allowCredentials,
                selectedCredentialId: selectedCred?.id
            )

            let parameters = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: allowList,
                extensions: ctapExtensions,
                up: true,
                uv: auth.uv
            )

            let collected: [CTAP2.GetAssertion.Response]
            do throws(CTAP2.SessionError) {
                let firstStream = await backend.getAssertion(
                    parameters: parameters,
                    token: auth.token
                )
                var firstResponse: CTAP2.GetAssertion.Response?
                for try await ctapStatus in firstStream {
                    switch ctapStatus {
                    case .processing:
                        continuation.yield(.processing)
                    case .waitingForUser(let cancel):
                        continuation.yield(.waitingForUser(cancel: cancel))
                    case .finished(let response):
                        firstResponse = response
                    }
                }

                guard let firstResponse else {
                    throw CTAP2.SessionError.responseParseError(
                        "Missing response from getAssertion",
                        source: .here()
                    )
                }

                // Collect additional assertions for discoverable credentials.
                var allResponses = [firstResponse]
                let total = firstResponse.numberOfCredentials ?? 1
                for _ in 1..<total {
                    allResponses.append(try await backend.getNextAssertion().value)
                }
                collected = allResponses
            } catch {
                guard retry.shouldRetry(for: error) else { throw WebAuthn.Error(error) }
                continue
            }

            // Build matched credentials with deferred extension processing.
            var matches: [WebAuthn.Authentication.MatchedCredential] = []
            for ctapResponse in collected {
                guard let credentialId = ctapResponse.credential?.id ?? allowList?.first?.id else {
                    throw WebAuthn.Error(
                        CTAP2.SessionError.responseParseError(
                            "Missing credential ID in assertion response",
                            source: .here()
                        )
                    )
                }

                // Capture values for the select closure.
                let backend = self.backend
                let token = auth.token

                let match = WebAuthn.Authentication.MatchedCredential(
                    id: credentialId,
                    user: ctapResponse.user,
                    select: { [ctapResponse, prf, largeBlobAction, clientData] () async throws(WebAuthn.Error) in
                        // Process largeBlob for this credential.
                        let largeBlobOutput = try await backend.processLargeBlob(
                            from: ctapResponse,
                            action: largeBlobAction,
                            token: token
                        )
                        // Parse extension outputs (PRF decrypt, etc.).
                        let extensionOutputs = try await backend.parseAuthenticationOutputs(
                            from: ctapResponse,
                            prf: prf,
                            largeBlobOutput: largeBlobOutput
                        )
                        return WebAuthn.Authentication.Response(
                            credentialId: credentialId,
                            rawAuthenticatorData: ctapResponse.authenticatorData.rawData,
                            signature: ctapResponse.signature,
                            user: ctapResponse.user,
                            authenticatorData: ctapResponse.authenticatorData,
                            clientExtensionResults: extensionOutputs,
                            clientDataJSON: clientData.clientDataJSON
                        )
                    }
                )
                matches.append(match)
            }
            return matches
        }
    }

    // Builds allow list: nil for discoverable, single match if found, dummy ID otherwise.
    // We still need to send a dummy value if there was an allowCredentials list but no matches
    // were found.
    fileprivate func buildAllowList(
        _ allowCredentials: [WebAuthn.CredentialDescriptor],
        selectedCred: WebAuthn.CredentialDescriptor?
    ) -> [WebAuthn.CredentialDescriptor]? {
        if allowCredentials.isEmpty { return nil }
        if let selectedCred { return [.init(id: selectedCred.id)] }
        return [.init(id: Data([0x00]))]
    }
}

// MARK: - Stream Mapping

extension WebAuthn.Status {
    fileprivate func mapResponse<T: Sendable>(_ transform: (Response) -> T) -> WebAuthn.Status<T> {
        switch self {
        case .processing: .processing
        case .waitingForUser(let cancel): .waitingForUser(cancel: cancel)
        case .requestingUV(let useUV): .requestingUV(useUV: useUV)
        case .finished(let response): .finished(transform(response))
        }
    }
}

extension StatusStreamBase {
    fileprivate func mapResponse<R: Sendable, T: Sendable>(
        _ transform: @escaping @Sendable (R) -> T
    ) -> StatusStreamBase<WebAuthn.Status<T>, WebAuthn.Error>
    where Status == WebAuthn.Status<R>, Failure == WebAuthn.Error {
        StatusStreamBase<WebAuthn.Status<T>, WebAuthn.Error> { continuation in
            Task {
                do {
                    for try await status in self {
                        continuation.yield(status.mapResponse(transform))
                    }
                } catch let error as WebAuthn.Error {
                    continuation.yield(error: error)
                }
            }
        }
    }
}

// MARK: - MatchedCredential Stream Helpers

extension StatusStreamBase
where Status == WebAuthn.Status<[WebAuthn.Authentication.MatchedCredential]>, Failure == WebAuthn.Error {

    /// Select the first matched credential and complete the assertion.
    fileprivate func selectFirst() -> WebAuthn.StatusStream<WebAuthn.Authentication.Response> {
        StatusStreamBase<WebAuthn.Status<WebAuthn.Authentication.Response>, WebAuthn.Error> { continuation in
            Task {
                do {
                    for try await status in self {
                        switch status {
                        case .processing:
                            continuation.yield(.processing)
                        case .waitingForUser(let cancel):
                            continuation.yield(.waitingForUser(cancel: cancel))
                        case .requestingUV(let useUV):
                            continuation.yield(.requestingUV(useUV: useUV))
                        case .finished(let matches):
                            let response = try await matches[0].select()
                            continuation.yield(.finished(response))
                        }
                    }
                } catch let error as WebAuthn.Error {
                    continuation.yield(error: error)
                }
            }
        }
    }
}
