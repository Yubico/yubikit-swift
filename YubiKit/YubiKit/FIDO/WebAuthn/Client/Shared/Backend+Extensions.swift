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

// MARK: - Extension Processing

extension WebAuthn.Backend {

    // MARK: - MakeCredential Extensions

    func buildMakeCredentialExtensions(
        _ inputs: WebAuthn.Extension.RegistrationInputs?
    ) async throws(WebAuthn.ClientError) -> (
        ctapInputs: [CTAP2.Extension.MakeCredential.Input],
        prf: WebAuthn.Extension.PRF?,
        largeBlobRequested: Bool
    ) {
        guard let inputs else {
            return ([], nil, false)
        }

        var ctapInputs: [CTAP2.Extension.MakeCredential.Input] = []
        var prf: WebAuthn.Extension.PRF?
        var largeBlobRequested = false

        do throws(CTAP2.SessionError) {
            if let prfInput = inputs.prf {
                if let p = try? await makePRF() {
                    if let eval = prfInput.eval {
                        ctapInputs.append(
                            try p.makeCredential.input(first: eval.first, second: eval.second)
                        )
                    } else {
                        ctapInputs.append(p.makeCredential.input())
                    }
                    prf = p
                }
            }

            if let credProtectInput = inputs.credProtect {
                let credProtect = try await makeCredProtect(
                    level: credProtectInput.policy,
                    enforce: credProtectInput.enforce
                )
                ctapInputs.append(credProtect.input())
            }

            if let credBlobData = inputs.credBlob {
                if let credBlob = try? await makeCredBlob() {
                    ctapInputs.append(try credBlob.makeCredential.input(blob: credBlobData))
                }
            }

            if let largeBlobInput = inputs.largeBlob {
                let supported = try await isLargeBlobSupported()
                if largeBlobInput.support == .required && !supported {
                    throw CTAP2.SessionError.extensionNotSupported(.largeBlobKey, source: .here())
                }
                // Always send the extension when requested (authenticator ignores if unsupported).
                // Response will indicate supported: true/false based on largeBlobKey presence.
                if supported {
                    let largeBlobKey = try await makeLargeBlobKey()
                    ctapInputs.append(largeBlobKey.makeCredential.input())
                }
                largeBlobRequested = true
            }
        } catch {
            throw WebAuthn.ClientError(error)
        }

        if inputs.minPinLength == true {
            do {
                if try await isMinPinLengthSupported() {
                    let minPinLength = try await makeMinPinLength()
                    ctapInputs.append(minPinLength.makeCredential.input())
                }
            } catch {
                // Ignore — minPinLength is best-effort.
            }
        }

        return (ctapInputs, prf, largeBlobRequested)
    }

    // MARK: - GetAssertion Extensions

    func buildGetAssertionExtensions(
        _ inputs: WebAuthn.Extension.AuthenticationInputs?,
        allowCredentials: [WebAuthn.CredentialDescriptor],
        selectedCredentialId: Data?
    ) async throws(WebAuthn.ClientError) -> (
        ctapInputs: [CTAP2.Extension.GetAssertion.Input],
        prf: WebAuthn.Extension.PRF?,
        largeBlobAction: WebAuthn.Extension.LargeBlob.Authentication.Input?
    ) {
        guard let inputs else {
            return ([], nil, nil)
        }

        var ctapInputs: [CTAP2.Extension.GetAssertion.Input] = []
        var prf: WebAuthn.Extension.PRF?
        var largeBlobAction: WebAuthn.Extension.LargeBlob.Authentication.Input?

        if let prfInput = inputs.prf {
            let evalByCredential: [Data: (first: Data, second: Data?)] = prfInput.evalByCredential.mapValues {
                ($0.first, $0.second)
            }

            // Validate evalByCredential against allowCredentials (WebAuthn L3 §10.1.4).
            if !evalByCredential.isEmpty && allowCredentials.isEmpty {
                throw .invalidRequest(
                    "evalByCredential requires non-empty allowCredentials",
                    source: .here()
                )
            }
            let allowedIds = Set(allowCredentials.map(\.id))
            for key in evalByCredential.keys where !allowedIds.contains(key) {
                throw .invalidRequest(
                    "evalByCredential key is not in allowCredentials",
                    source: .here()
                )
            }

            guard prfInput.eval != nil || !evalByCredential.isEmpty else {
                throw .invalidRequest("PRF requires eval or evalByCredential", source: .here())
            }

            // No matching credential and no default eval — skip PRF entirely.
            if prfInput.eval != nil || selectedCredentialId != nil {
                if let eval = prfInput.eval {
                    prf = try? await makePRF(
                        first: eval.first,
                        second: eval.second,
                        evalByCredential: evalByCredential
                    )
                } else {
                    prf = try? await makePRF(evalByCredential: evalByCredential)
                }
                if let prf {
                    do throws(CTAP2.SessionError) {
                        if let prfInput = try prf.getAssertion.input(for: selectedCredentialId) {
                            ctapInputs.append(prfInput)
                        }
                    } catch {
                        throw WebAuthn.ClientError(error)
                    }
                }
            }
        }

        if inputs.getCredBlob == true {
            if let credBlob = try? await makeCredBlob() {
                ctapInputs.append(credBlob.getAssertion.input())
            }
        }

        if let largeBlobInput = inputs.largeBlob {
            do throws(CTAP2.SessionError) {
                let largeBlobKey = try await makeLargeBlobKey()
                ctapInputs.append(largeBlobKey.getAssertion.input())
                largeBlobAction = largeBlobInput
            } catch {
                // For write requests, propagate errors — silent failure is data loss.
                // For read requests, skip silently (matches spec: "blob member will not be present").
                if case .write = largeBlobInput {
                    throw WebAuthn.ClientError(error)
                }
            }
        }

        return (ctapInputs, prf, largeBlobAction)
    }

    // MARK: - Output Parsing

    func parseRegistrationOutputs(
        from response: CTAP2.MakeCredential.Response,
        prf: WebAuthn.Extension.PRF?,
        largeBlobRequested: Bool,
        credPropsRk: Bool?
    ) throws(WebAuthn.ClientError) -> WebAuthn.Extension.RegistrationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.Registration.Output?

        if let prf {
            do throws(CTAP2.SessionError) {
                if let ctapResult = try prf.makeCredential.output(from: response) {
                    prfOutput = .init(ctapResult: ctapResult)
                }
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }

        let extensions = response.authenticatorData.extensions

        let credProtectOutput: WebAuthn.Extension.CredProtect.Registration.Output? =
            extensions?[.credProtect]
            .flatMap { WebAuthn.Extension.CredProtect.Policy(cbor: $0) }
            .map { .init(policy: $0) }

        let credBlobOutput: WebAuthn.Extension.CredBlob.Registration.Output? =
            extensions?[.credBlob]?.boolValue.map { .init(stored: $0) }

        let minPinLengthOutput: WebAuthn.Extension.MinPinLength.Registration.Output? =
            extensions?[.minPinLength]?.uint64Value.map { .init(length: UInt($0)) }

        let largeBlobOutput: WebAuthn.Extension.LargeBlob.Registration.Output? =
            largeBlobRequested
            ? .init(supported: response.largeBlobKey != nil)
            : nil

        let credPropsOutput: WebAuthn.Extension.CredProps.Registration.Output? =
            credPropsRk.map { .init(rk: $0) }

        return WebAuthn.Extension.RegistrationOutputs(
            prf: prfOutput,
            credProtect: credProtectOutput,
            credBlob: credBlobOutput,
            minPinLength: minPinLengthOutput,
            largeBlob: largeBlobOutput,
            credProps: credPropsOutput
        )
    }

    func parseAuthenticationOutputs(
        from response: CTAP2.GetAssertion.Response,
        prf: WebAuthn.Extension.PRF?,
        largeBlobOutput: WebAuthn.Extension.LargeBlob.Authentication.Output?
    ) throws(WebAuthn.ClientError) -> WebAuthn.Extension.AuthenticationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.Authentication.Output?

        if let prf {
            do throws(CTAP2.SessionError) {
                if let ctapSecrets = try prf.getAssertion.output(from: response) {
                    prfOutput = .init(ctapSecrets: ctapSecrets)
                }
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }

        let credBlobOutput: WebAuthn.Extension.CredBlob.Authentication.Output? =
            response.authenticatorData.extensions?[.credBlob]?.dataValue.map { .init(blob: $0) }

        return WebAuthn.Extension.AuthenticationOutputs(
            prf: prfOutput,
            credBlob: credBlobOutput,
            largeBlob: largeBlobOutput
        )
    }

    // MARK: - Large Blob Processing

    func processLargeBlob(
        from response: CTAP2.GetAssertion.Response,
        action: WebAuthn.Extension.LargeBlob.Authentication.Input?,
        token: CTAP2.Token?
    ) async throws(WebAuthn.ClientError) -> WebAuthn.Extension.LargeBlob.Authentication.Output? {
        guard let action, let key = response.largeBlobKey else { return nil }

        switch action {
        case .read:
            // Reads fail silently per spec ("blob member will not be present")
            let blob = try? await getBlob(key: key)
            return .init(blob: blob)
        case .write(let data):
            guard let token else {
                throw .internalError("largeBlob.write requires PIN/UV token", source: .here())
            }
            do {
                try await putBlob(key: key, data: data, token: token)
                return .init(written: true)
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }
    }
}
