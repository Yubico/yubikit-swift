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
        return WebAuthn.StatusStream { continuation in
            Task { [self] in
                do throws(WebAuthn.ClientError) {
                    let response = try await performMakeCredential(
                        options: options,
                        clientData: clientData,
                        authorization: authorization,
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

    fileprivate func performMakeCredential(
        options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        continuation: WebAuthn.StatusStream<WebAuthn.Registration.Response>.Continuation
    ) async throws(WebAuthn.ClientError) -> WebAuthn.Registration.Response {

        let cachedInfo: CTAP2.GetInfo.ImmutableView
        do throws(CTAP2.SessionError) {
            cachedInfo = try await backend.cachedInfo
        } catch {
            throw WebAuthn.ClientError(error)
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

        while true {
            // Re-fetch mutable state (PIN/UV counters) on each attempt.
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
                isMakeCredential: true,
                allowUV: retry.allowUV,
                authorization: authorization,
                yieldProcessing: { continuation.yield(.processing) },
                yieldUVWaiting: { cancel, fallback in
                    continuation.yield(
                        .waitingForUserVerification(cancel: cancel, fallbackToPIN: fallback)
                    )
                }
            )

            let excludedCred = try await findMatchingCredential(
                from: options.excludeCredentials,
                rpId: rpId,
                cachedInfo: cachedInfo,
                token: auth.token
            )

            let (ctapExtensions, prf, previewSign, largeBlobRequested) =
                try await backend.buildMakeCredentialExtensions(
                    options.extensions,
                    allowedExtensions: allowedExtensions,
                    userVerification: options.userVerification
                )

            let parameters = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: .init(id: rpId, name: options.rp.name),
                user: .init(id: options.user.id, name: options.user.name, displayName: options.user.displayName),
                pubKeyCredParams: options.pubKeyCredParams,
                excludeList: excludedCred.map { [.init(id: $0.id)] },
                extensions: ctapExtensions,
                rk: rk,
                uv: auth.uv,
                enterpriseAttestation: enterpriseAttestation
            )

            let ctapResponse: CTAP2.MakeCredential.Response
            do throws(CTAP2.SessionError) {
                let ctapStream = await backend.makeCredential(
                    parameters: parameters,
                    token: auth.token
                )
                var receivedResponse: CTAP2.MakeCredential.Response?
                for try await ctapStatus in ctapStream {
                    switch ctapStatus {
                    case .processing:
                        continuation.yield(.processing)
                    case .waitingForUser(let cancel):
                        continuation.yield(.waitingForUser(cancel: cancel))
                    case .finished(let response):
                        receivedResponse = response
                    }
                }
                guard let response = receivedResponse else {
                    throw CTAP2.SessionError.responseParseError(
                        "No response from makeCredential",
                        source: .here()
                    )
                }
                ctapResponse = response
            } catch {
                guard retry.shouldRetry(for: error) else {
                    if case .ctapError(.uvInvalid, _) = error {
                        throw try await translateUVInvalid()
                    }
                    throw WebAuthn.ClientError(error)
                }
                continue
            }

            let authenticatorData = ctapResponse.authenticatorData
            guard let attestedCredentialData = authenticatorData.attestedCredentialData else {
                throw WebAuthn.ClientError(
                    CTAP2.SessionError.responseParseError(
                        "Missing attested credential data in makeCredential response",
                        source: .here()
                    )
                )
            }
            let credPropsRk: Bool? = options.extensions?.credProps == true ? rk : nil
            let extensionOutputs = try await backend.parseRegistrationOutputs(
                from: ctapResponse,
                prf: prf,
                previewSign: previewSign,
                largeBlobRequested: largeBlobRequested,
                credPropsRk: credPropsRk,
                allowedExtensions: allowedExtensions
            )
            return WebAuthn.Registration.Response(
                credentialId: attestedCredentialData.credentialId,
                rawAttestationObject: ctapResponse.attestationObject.rawData,
                rawAuthenticatorData: authenticatorData.rawData,
                attestationStatement: ctapResponse.attestationObject.statement,
                transports: cachedInfo.transports,
                clientExtensionResults: extensionOutputs,
                publicKey: attestedCredentialData.credentialPublicKey,
                aaguid: attestedCredentialData.aaguid,
                signCount: authenticatorData.signCount,
                authenticatorData: authenticatorData,
                clientDataJSON: clientData.clientDataJSON
            )
        }
    }

    // Maps WebAuthn resident key preference to CTAP2 `rk` boolean.
    fileprivate func resolveResidentKey(
        _ preference: WebAuthn.ResidentKeyPreference,
        cachedInfo: CTAP2.GetInfo.ImmutableView
    ) throws(WebAuthn.ClientError) -> Bool {
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
