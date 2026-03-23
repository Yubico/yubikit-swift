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

extension WebAuthn {

    actor CTAP2Backend: Backend {

        private let session: CTAP2.Session
        private let pinProvider: PINProvider?
        private let enterpriseRpIds: Set<String>

        private struct RetryState {
            var userVerification: UserVerificationPreference
            var allowUV: Bool = true

            mutating func shouldRetry(for error: CTAP2.SessionError) -> Bool {
                switch error {
                case .ctapError(.puatRequired, _) where userVerification == .discouraged:
                    userVerification = .required
                    return true
                case .ctapError(.uvBlocked, _) where allowUV:
                    allowUV = false
                    return true
                default:
                    return false
                }
            }
        }

        private struct AuthParams {
            let token: CTAP2.Token?
            let internalUV: Bool

            var uv: Bool? { internalUV ? true : nil }
        }

        init(
            session: CTAP2.Session,
            pinProvider: PINProvider?,
            enterpriseRpIds: Set<String>
        ) {
            self.session = session
            self.pinProvider = pinProvider
            self.enterpriseRpIds = enterpriseRpIds
        }

        // MARK: - Public API

        func makeCredential(
            options: Registration.Options,
            clientData: ClientData
        ) async -> StatusStream<Registration.Response> {
            StatusStream { continuation in
                Task { [self] in
                    do throws(ClientError) {
                        let response = try await performMakeCredential(
                            options: options,
                            clientData: clientData,
                            continuation: continuation
                        )
                        continuation.yield(.finished(response))
                    } catch {
                        continuation.yield(error: error)
                    }
                }
            }
        }

        func getAssertion(
            options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<Authentication.Response> {
            StatusStream { continuation in
                Task { [self] in
                    do throws(ClientError) {
                        let assertions = try await performGetAssertions(
                            options: options,
                            clientData: clientData,
                            continuation: continuation
                        )
                        guard let first = assertions.first else {
                            throw ClientError.noCredentials(source: .here())
                        }
                        continuation.yield(.finished(first.response))
                    } catch {
                        continuation.yield(error: error)
                    }
                }
            }
        }

        func getAssertions(
            options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<[Authentication.Assertion]> {
            StatusStream { continuation in
                Task { [self] in
                    do throws(ClientError) {
                        let assertions = try await performGetAssertions(
                            options: options,
                            clientData: clientData,
                            continuation: nil
                        )
                        guard !assertions.isEmpty else {
                            throw ClientError.noCredentials(source: .here())
                        }
                        continuation.yield(.finished(assertions))
                    } catch {
                        continuation.yield(error: error)
                    }
                }
            }
        }

        // MARK: - MakeCredential Implementation

        private func performMakeCredential(
            options: Registration.Options,
            clientData: ClientData,
            continuation: StatusStream<Registration.Response>.Continuation
        ) async throws(ClientError) -> Registration.Response {
            let cachedInfo: CTAP2.GetInfo.ImmutableView
            do throws(CTAP2.SessionError) {
                cachedInfo = try await session.cachedInfo
            } catch {
                throw ClientError(error)
            }

            let rpId = clientData.rpId
            let rk = try resolveResidentKey(options.residentKey, cachedInfo: cachedInfo)
            let enterpriseAttestation = resolveEnterpriseAttestation(
                options.attestation,
                rpId: rpId,
                cachedInfo: cachedInfo
            )
            let permissions: CTAP2.ClientPin.Permission =
                options.excludeCredentials.isEmpty ? .makeCredential : [.makeCredential, .getAssertion]
            let clientDataHash = clientData.clientDataHash

            var retry = RetryState(userVerification: options.userVerification)

            while true {
                let info: CTAP2.GetInfo.Response
                do throws(CTAP2.SessionError) {
                    info = try await session.getInfo()
                } catch {
                    throw ClientError(error)
                }
                let authParams = try await getAuthParams(
                    info: info,
                    permissions: permissions,
                    rpId: rpId,
                    userVerification: retry.userVerification,
                    isMakeCredential: true,
                    allowUV: retry.allowUV,
                    requestUVApproval: { await self.awaitUVDecision(from: continuation) }
                )

                let excludedCred = try await filterCredentials(
                    options.excludeCredentials,
                    rpId: rpId,
                    cachedInfo: cachedInfo,
                    token: authParams.token
                )

                let parameters = CTAP2.MakeCredential.Parameters(
                    clientDataHash: clientDataHash,
                    rp: .init(id: rpId, name: options.rp.name),
                    user: .init(id: options.user.id, name: options.user.name, displayName: options.user.displayName),
                    pubKeyCredParams: options.pubKeyCredParams,
                    excludeList: excludedCred.map { [.init(id: $0.id)] },
                    extensions: [],  // TODO: credProtect, prf, largeBlob
                    rk: rk,
                    uv: authParams.uv,
                    enterpriseAttestation: enterpriseAttestation
                )

                do throws(CTAP2.SessionError) {
                    let ctapStream = await session.makeCredential(
                        parameters: parameters,
                        token: authParams.token
                    )
                    for try await ctapStatus in ctapStream {
                        switch ctapStatus {
                        case .processing:
                            continuation.yield(.processing)
                        case .waitingForUser(let cancel):
                            continuation.yield(.waitingForUser(cancel: cancel))
                        case .finished(let ctapResponse):
                            guard
                                let credentialId = ctapResponse.authenticatorData
                                    .attestedCredentialData?.credentialId
                            else {
                                throw CTAP2.SessionError.responseParseError(
                                    "Missing credential ID in makeCredential response",
                                    source: .here()
                                )
                            }
                            return Registration.Response(
                                credentialId: credentialId,
                                rawAttestationObject: ctapResponse.attestationObject.rawData,
                                authenticatorData: ctapResponse.authenticatorData,
                                attestationStatement: ctapResponse.attestationObject.statement,
                                transports: cachedInfo.transports,
                                clientDataJSON: clientData.clientDataJSON
                            )
                        }
                    }
                    throw CTAP2.SessionError.responseParseError(
                        "No response from makeCredential",
                        source: .here()
                    )
                } catch {
                    guard retry.shouldRetry(for: error) else { throw ClientError(error) }
                }
            }
        }

        private func resolveResidentKey(
            _ preference: ResidentKeyPreference,
            cachedInfo: CTAP2.GetInfo.ImmutableView
        ) throws(ClientError) -> Bool {
            let supported = cachedInfo.options.residentKey
            if preference == .required && !supported {
                throw .notSupported("Resident key not supported", source: .here())
            }
            return preference == .required || (preference == .preferred && supported)
        }

        private func resolveEnterpriseAttestation(
            _ attestation: AttestationPreference,
            rpId: String,
            cachedInfo: CTAP2.GetInfo.ImmutableView
        ) -> Int? {
            guard attestation == .enterprise, cachedInfo.options.supportsEnterpriseAttestation else { return nil }
            return enterpriseRpIds.contains(rpId) ? 2 : 1
        }

        // MARK: - GetAssertion Implementation

        private func performGetAssertions(
            options: Authentication.Options,
            clientData: ClientData,
            continuation: StatusStream<Authentication.Response>.Continuation?
        ) async throws(ClientError) -> [Authentication.Assertion] {
            let cachedInfo: CTAP2.GetInfo.ImmutableView
            do throws(CTAP2.SessionError) {
                cachedInfo = try await session.cachedInfo
            } catch {
                throw ClientError(error)
            }
            let rpId = clientData.rpId
            let clientDataHash = clientData.clientDataHash

            var retry = RetryState(userVerification: options.userVerification)

            while true {
                let info: CTAP2.GetInfo.Response
                do throws(CTAP2.SessionError) {
                    info = try await session.getInfo()
                } catch {
                    throw ClientError(error)
                }
                let requestUVApproval: (@Sendable () async -> Bool)? =
                    if let cont = continuation {
                        { await self.awaitUVDecision(from: cont) }
                    } else {
                        nil
                    }
                let authParams = try await getAuthParams(
                    info: info,
                    permissions: .getAssertion,
                    rpId: rpId,
                    userVerification: retry.userVerification,
                    isMakeCredential: false,
                    allowUV: retry.allowUV,
                    requestUVApproval: requestUVApproval
                )

                let selectedCred = try await filterCredentials(
                    options.allowCredentials,
                    rpId: rpId,
                    cachedInfo: cachedInfo,
                    token: authParams.token
                )

                let allowList = buildAllowList(options.allowCredentials, selectedCred: selectedCred)

                let parameters = CTAP2.GetAssertion.Parameters(
                    rpId: rpId,
                    clientDataHash: clientDataHash,
                    allowList: allowList,
                    extensions: [],  // TODO: credProtect, prf, largeBlob
                    up: true,
                    uv: authParams.uv
                )

                do throws(CTAP2.SessionError) {
                    let firstStream = await session.getAssertion(
                        parameters: parameters,
                        token: authParams.token
                    )
                    var firstResponse: CTAP2.GetAssertion.Response?
                    for try await ctapStatus in firstStream {
                        switch ctapStatus {
                        case .processing:
                            continuation?.yield(.processing)
                        case .waitingForUser(let cancel):
                            continuation?.yield(.waitingForUser(cancel: cancel))
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

                    var collected = [firstResponse]
                    let total = firstResponse.numberOfCredentials ?? 1
                    for _ in 1..<total {
                        collected.append(try await session.getNextAssertion().value)
                    }

                    var assertions: [Authentication.Assertion] = []
                    for ctapResponse in collected {
                        guard
                            let credentialId = ctapResponse.credential?.id
                                ?? options.allowCredentials.first?.id
                        else {
                            throw CTAP2.SessionError.responseParseError(
                                "Missing credential ID in assertion response",
                                source: .here()
                            )
                        }
                        let assertion = Authentication.Assertion(
                            credentialId: credentialId,
                            userHandle: ctapResponse.user?.id,
                            userName: ctapResponse.user?.name,
                            userDisplayName: ctapResponse.user?.displayName,
                            response: Authentication.Response(
                                credentialId: credentialId,
                                rawAuthenticatorData: ctapResponse.authenticatorData.rawData,
                                signature: ctapResponse.signature,
                                userHandle: ctapResponse.user?.id,
                                authenticatorData: ctapResponse.authenticatorData,
                                clientDataJSON: clientData.clientDataJSON
                            )
                        )
                        assertions.append(assertion)
                    }
                    return assertions
                } catch {
                    guard retry.shouldRetry(for: error) else { throw ClientError(error) }
                }
            }
        }

        private func buildAllowList(
            _ allowCredentials: [CredentialDescriptor],
            selectedCred: CredentialDescriptor?
        ) -> [WebAuthn.CredentialDescriptor]? {
            if allowCredentials.isEmpty { return nil }
            if let selectedCred { return [.init(id: selectedCred.id)] }
            // No match found, send dummy to ensure UP is prompted before failing
            return [.init(id: Data([0x00]))]
        }

        // MARK: - Common Helpers

        private func awaitUVDecision<R: Sendable>(
            from continuation: StatusStream<R>.Continuation
        ) async -> Bool {
            await withCheckedContinuation { checkedContinuation in
                continuation.yield(
                    .requestingUV { proceed in
                        checkedContinuation.resume(returning: proceed)
                    }
                )
            }
        }

        private func shouldUseUV(
            info: CTAP2.GetInfo.Response,
            userVerification: UserVerificationPreference,
            permissions: CTAP2.ClientPin.Permission,
            isMakeCredential: Bool
        ) throws(ClientError) -> Bool {
            let options = info.options

            let uvSupported =
                options.userVerification != nil
                || options.clientPin != nil
                || options.bioEnroll != nil

            let uvConfigured =
                options.userVerification == true
                || options.clientPin == true
                || options.bioEnroll == true

            if userVerification == .required
                || (userVerification == .preferred && uvSupported)
                || (userVerification == .discouraged && options.clientPin == true)
                || options.alwaysUV == true
            {
                guard uvConfigured else {
                    throw .notSupported("User verification not configured/supported", source: .here())
                }
                return true
            }

            if isMakeCredential && uvConfigured && options.makeCredUVNotRequired != true {
                return true
            }

            let additionalPerms = permissions.subtracting([.makeCredential, .getAssertion])
            if uvConfigured && !additionalPerms.isEmpty {
                return true
            }

            return false
        }

        private func filterCredentials(
            _ credentials: [CredentialDescriptor],
            rpId: String,
            cachedInfo: CTAP2.GetInfo.ImmutableView,
            token: CTAP2.Token?
        ) async throws(ClientError) -> CredentialDescriptor? {
            guard !credentials.isEmpty else { return nil }

            let maxLength = cachedInfo.maxCredentialIdLength.map { Int($0) }
            var filtered = credentials.filter { cred in
                guard let maxLength else { return true }
                return cred.id.count <= maxLength
            }
            guard !filtered.isEmpty else { return nil }

            var maxChunkSize = cachedInfo.maxCredentialCountInList.map { Int($0) } ?? 1
            let dummyClientDataHash = Data(repeating: 0, count: 32)

            while !filtered.isEmpty && maxChunkSize > 0 {
                let chunkSize = min(maxChunkSize, filtered.count)
                let chunk = Array(filtered.prefix(chunkSize))

                let parameters = CTAP2.GetAssertion.Parameters(
                    rpId: rpId,
                    clientDataHash: dummyClientDataHash,
                    allowList: chunk.map { .init(id: $0.id) },
                    extensions: [],
                    up: false
                )

                do throws(CTAP2.SessionError) {
                    let response = try await session.getAssertion(parameters: parameters, token: token).value
                    if chunk.count == 1 { return chunk[0] }
                    if let matchedId = response.credential?.id {
                        return chunk.first { $0.id == matchedId }
                    }
                    throw .responseParseError(
                        "Expecting exactly one credential in allowList when credential ID is omitted",
                        source: .here()
                    )
                } catch {
                    switch error {
                    case .ctapError(.noCredentials, _):
                        filtered.removeFirst(chunkSize)
                    case .ctapError(.requestTooLarge, _) where maxChunkSize > 1:
                        maxChunkSize -= 1
                    default:
                        throw ClientError(error)
                    }
                }
            }

            return nil
        }

        private func getAuthParams(
            info: CTAP2.GetInfo.Response,
            permissions: CTAP2.ClientPin.Permission,
            rpId: String,
            userVerification: UserVerificationPreference,
            isMakeCredential: Bool,
            allowUV: Bool = true,
            requestUVApproval: (@Sendable () async -> Bool)? = nil
        ) async throws(ClientError) -> AuthParams {
            let uvRequired = try shouldUseUV(
                info: info,
                userVerification: userVerification,
                permissions: permissions,
                isMakeCredential: isMakeCredential
            )
            guard uvRequired else {
                return AuthParams(token: nil, internalUV: false)
            }

            let hasPin = info.options.clientPin == true
            let hasUV = info.options.userVerification == true
            let allowInternalUV = permissions.subtracting([.makeCredential, .getAssertion]).isEmpty

            let uvRetries = hasUV && allowUV ? (try? await session.getUVRetries()) ?? 0 : 0

            if uvRetries > 0, info.options.pinUVAuthToken == true {
                // Ask user before attempting UV (Python's request_uv pattern)
                // If no approval callback, default to proceeding with UV
                let proceedWithUV = await requestUVApproval?() ?? true

                if proceedWithUV {
                    do throws(CTAP2.SessionError) {
                        let token = try await session.getPinUVToken(
                            using: .uv,
                            permissions: permissions,
                            rpId: rpId
                        )
                        return AuthParams(token: token, internalUV: false)
                    } catch {
                        switch error {
                        case .ctapError(.uvBlocked, _),
                            .ctapError(.operationDenied, _),
                            .ctapError(.unauthorizedPermission, _):
                            guard hasPin else {
                                let retries = try? await session.getUVRetries()
                                throw .userVerificationFailed(
                                    retriesRemaining: retries,
                                    source: .here()
                                )
                            }
                        default:
                            throw ClientError(error)
                        }
                    }
                }
                // Fall through to PIN-based authentication
            } else if uvRetries > 0, allowInternalUV {
                return AuthParams(token: nil, internalUV: true)
            }

            guard let pinProvider else {
                throw .pinRequired(source: .here())
            }
            guard let pin = await pinProvider() else {
                throw .cancelled(source: .here())
            }

            do throws(CTAP2.SessionError) {
                let token = try await session.getPinUVToken(
                    using: .pin(pin),
                    permissions: permissions,
                    rpId: rpId
                )
                return AuthParams(token: token, internalUV: false)
            } catch {
                if case .ctapError(.pinInvalid, _) = error {
                    let retries = (try? await session.getPinRetries())?.retries ?? 0
                    throw .invalidPIN(retriesRemaining: retries, source: .here())
                }
                throw ClientError(error)
            }
        }
    }
}
