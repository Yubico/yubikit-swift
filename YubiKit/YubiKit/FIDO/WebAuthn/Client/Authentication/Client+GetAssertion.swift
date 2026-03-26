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
        return await getAssertions(options, clientData: clientData).mapResponse { $0[0] }
    }

    /// Get all matching responses for credential selection UI.
    ///
    /// Uses the client's origin and validates the RP ID.
    public func getAssertions(
        _ options: WebAuthn.Authentication.Options
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        let rpId = options.rpId ?? origin.host
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.get",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await getAssertions(options, clientData: clientData)
    }

    /// Get all matching responses using custom client data.
    public func getAssertions(
        _ options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.Error) {
                    let assertions = try await performGetAssertions(
                        options: options,
                        clientData: clientData,
                        continuation: continuation
                    )
                    guard !assertions.isEmpty else {
                        throw WebAuthn.Error.noCredentials(source: .here())
                    }
                    continuation.yield(.finished(assertions))
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
    fileprivate func performGetAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        continuation: WebAuthn.StatusStream<[WebAuthn.Authentication.Response]>.Continuation
    ) async throws(WebAuthn.Error) -> [WebAuthn.Authentication.Response] {

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

            let auth = try await acquireAuthToken(
                info: info,
                permissions: .getAssertion,
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

            let parameters = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: allowList,
                extensions: [],  // TODO: Extensions not yet implemented
                up: true,
                uv: auth.uv
            )

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
                var collected = [firstResponse]
                let total = firstResponse.numberOfCredentials ?? 1
                for _ in 1..<total {
                    collected.append(try await backend.getNextAssertion().value)
                }

                var responses: [WebAuthn.Authentication.Response] = []
                for ctapResponse in collected {
                    // Credential ID from response, or allowList (may be omitted for single-item).
                    guard let credentialId = ctapResponse.credential?.id ?? allowList?.first?.id else {
                        throw CTAP2.SessionError.responseParseError(
                            "Missing credential ID in assertion response",
                            source: .here()
                        )
                    }
                    let response = WebAuthn.Authentication.Response(
                        credentialId: credentialId,
                        rawAuthenticatorData: ctapResponse.authenticatorData.rawData,
                        signature: ctapResponse.signature,
                        user: ctapResponse.user,
                        authenticatorData: ctapResponse.authenticatorData,
                        clientDataJSON: clientData.clientDataJSON
                    )
                    responses.append(response)
                }
                return responses
            } catch {
                guard retry.shouldRetry(for: error) else { throw WebAuthn.Error(error) }
            }
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
