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
    /// Uses the client's origin and validates the RP ID.
    public func makeCredential(
        _ options: WebAuthn.Registration.Options
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        let rpId = options.rp.id
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.create",
            challenge: options.challenge,
            origin: origin,
            rpId: rpId
        )
        return await makeCredential(options, clientData: clientData)
    }

    /// Create a new passkey credential with custom client data.
    public func makeCredential(
        _ options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
            return .error(error)
        }
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.Error) {
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
        }.withTimeout(options.timeout)
    }
}

// MARK: - Private Implementation

extension WebAuthn.Client {

    // Executes the CTAP2 makeCredential flow with PIN/UV handling and retry logic.
    fileprivate func performMakeCredential(
        options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData,
        continuation: WebAuthn.StatusStream<WebAuthn.Registration.Response>.Continuation
    ) async throws(WebAuthn.Error) -> WebAuthn.Registration.Response {

        // Fetch cached immutable authenticator capabilities.
        let cachedInfo: CTAP2.GetInfo.ImmutableView
        do throws(CTAP2.SessionError) {
            cachedInfo = try await backend.cachedInfo
        } catch {
            throw WebAuthn.Error(error)
        }

        let rpId = clientData.rpId
        let rk = try resolveResidentKey(options.residentKey, cachedInfo: cachedInfo)
        let enterpriseAttestation = resolveEnterpriseAttestation(
            options.attestation,
            rpId: rpId,
            cachedInfo: cachedInfo
        )
        // Need getAssertion permission to silently probe exclude list.
        let permissions: CTAP2.ClientPin.Permission =
            options.excludeCredentials.isEmpty ? .makeCredential : [.makeCredential, .getAssertion]
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

            let auth = try await acquireAuthToken(
                info: info,
                permissions: permissions,
                rpId: rpId,
                userVerification: retry.userVerification,
                isMakeCredential: true,
                allowUV: retry.allowUV,
                requestUVApproval: { await self.awaitUVDecision(from: continuation) }
            )

            // Silently check if user already has a credential (exclude list).
            let excludedCred = try await findMatchingCredential(
                from: options.excludeCredentials,
                rpId: rpId,
                cachedInfo: cachedInfo,
                token: auth.token
            )

            let parameters = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: .init(id: rpId, name: options.rp.name),
                user: .init(id: options.user.id, name: options.user.name, displayName: options.user.displayName),
                pubKeyCredParams: options.pubKeyCredParams,
                excludeList: excludedCred.map { [.init(id: $0.id)] },
                extensions: [],  // TODO: Extensions not yet implemented
                rk: rk,
                uv: auth.uv,
                enterpriseAttestation: enterpriseAttestation
            )

            do throws(CTAP2.SessionError) {
                let ctapStream = await backend.makeCredential(
                    parameters: parameters,
                    token: auth.token
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
                        return WebAuthn.Registration.Response(
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
                guard retry.shouldRetry(for: error) else { throw WebAuthn.Error(error) }
            }
        }
    }

    // Maps WebAuthn resident key preference to CTAP2 `rk` boolean.
    fileprivate func resolveResidentKey(
        _ preference: WebAuthn.ResidentKeyPreference,
        cachedInfo: CTAP2.GetInfo.ImmutableView
    ) throws(WebAuthn.Error) -> Bool {
        let supported = cachedInfo.options.residentKey
        if preference == .required && !supported {
            throw .notSupported("Resident key not supported", source: .here())
        }
        return preference == .required || (preference == .preferred && supported)
    }

    // Resolves enterprise attestation level (1=vendor-facilitated, 2=platform-managed).
    fileprivate func resolveEnterpriseAttestation(
        _ attestation: WebAuthn.AttestationPreference,
        rpId: String,
        cachedInfo: CTAP2.GetInfo.ImmutableView
    ) -> Int? {
        guard attestation == .enterprise, cachedInfo.options.supportsEnterpriseAttestation else { return nil }
        return enterpriseRpIds.contains(rpId) ? 2 : 1
    }
}
