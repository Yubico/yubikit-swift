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
    ) async throws(WebAuthn.Error) -> (
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

            if let policy = inputs.credentialProtectionPolicy {
                let credProtect = try await makeCredProtect(
                    level: policy,
                    enforce: inputs.enforceCredentialProtectionPolicy
                )
                ctapInputs.append(credProtect.input())
            }

            if let blob = inputs.credBlob {
                if let credBlob = try? await makeCredBlob() {
                    ctapInputs.append(try credBlob.makeCredential.input(blob: blob))
                }
            }

            if let largeBlobInput = inputs.largeBlob {
                let supported = try await isLargeBlobSupported()
                if supported {
                    let largeBlobKey = try await makeLargeBlobKey()
                    ctapInputs.append(largeBlobKey.makeCredential.input())
                    largeBlobRequested = true
                } else if largeBlobInput.support == .required {
                    throw CTAP2.SessionError.extensionNotSupported(.largeBlobKey, source: .here())
                }
            }
        } catch {
            throw WebAuthn.Error(error)
        }

        if inputs.minPinLength {
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
    ) async throws(WebAuthn.Error) -> (
        ctapInputs: [CTAP2.Extension.GetAssertion.Input],
        prf: WebAuthn.Extension.PRF?,
        largeBlobAction: WebAuthn.Extension.LargeBlob.AuthenticationInput?
    ) {
        guard let inputs else {
            return ([], nil, nil)
        }

        var ctapInputs: [CTAP2.Extension.GetAssertion.Input] = []
        var prf: WebAuthn.Extension.PRF?
        var largeBlobAction: WebAuthn.Extension.LargeBlob.AuthenticationInput?

        if let prfInput = inputs.prf {
            let evalByCredential: [Data: (first: Data, second: Data?)] = prfInput.evalByCredential.mapValues {
                ($0.first, $0.second)
            }

            // Validate evalByCredential against allowCredentials (WebAuthn L3 §10.1.4).
            if !evalByCredential.isEmpty {
                if allowCredentials.isEmpty {
                    throw .invalidRequest(
                        "evalByCredential requires non-empty allowCredentials",
                        source: .here()
                    )
                }
                let allowedIds = Set(allowCredentials.map(\.id))
                for key in evalByCredential.keys {
                    if !allowedIds.contains(key) {
                        throw .invalidRequest(
                            "evalByCredential key is not in allowCredentials",
                            source: .here()
                        )
                    }
                }
            }

            guard prfInput.eval != nil || !evalByCredential.isEmpty else {
                throw .invalidRequest("PRF requires eval or evalByCredential", source: .here())
            }

            // No matching credential and no default eval — skip PRF entirely.
            // The authenticator will return noCredentials on the dummy allowList.
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
                        throw WebAuthn.Error(error)
                    }
                }
            }
        }

        if inputs.getCredBlob {
            if let credBlob = try? await makeCredBlob() {
                ctapInputs.append(credBlob.getAssertion.input())
            }
        }

        if inputs.largeBlob != nil {
            if let largeBlobKey = try? await makeLargeBlobKey() {
                ctapInputs.append(largeBlobKey.getAssertion.input())
                largeBlobAction = inputs.largeBlob
            }
        }

        return (ctapInputs, prf, largeBlobAction)
    }

    // MARK: - Output Parsing

    func parseRegistrationOutputs(
        from response: CTAP2.MakeCredential.Response,
        prf: WebAuthn.Extension.PRF?,
        largeBlobRequested: Bool
    ) throws(WebAuthn.Error) -> WebAuthn.Extension.RegistrationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.RegistrationOutput?

        if let prf {
            do throws(CTAP2.SessionError) {
                prfOutput = try prf.makeCredential.output(from: response)
            } catch {
                throw WebAuthn.Error(error)
            }
        }

        let extensions = response.authenticatorData.extensions
        let credProtect = extensions?[.credProtect].flatMap {
            WebAuthn.Extension.CredentialProtectionPolicy(cbor: $0)
        }
        let credBlob = extensions?[.credBlob]?.boolValue
        let minPinLength = extensions?[.minPinLength]?.uint64Value.map { UInt($0) }

        let largeBlobOutput: WebAuthn.Extension.LargeBlob.RegistrationOutput? =
            largeBlobRequested
            ? .init(supported: response.largeBlobKey != nil)
            : nil

        return WebAuthn.Extension.RegistrationOutputs(
            prf: prfOutput,
            credentialProtectionPolicy: credProtect,
            credBlobSet: credBlob,
            minPinLength: minPinLength,
            largeBlob: largeBlobOutput
        )
    }

    func parseAuthenticationOutputs(
        from response: CTAP2.GetAssertion.Response,
        prf: WebAuthn.Extension.PRF?,
        largeBlobOutput: WebAuthn.Extension.LargeBlob.AuthenticationOutput?
    ) throws(WebAuthn.Error) -> WebAuthn.Extension.AuthenticationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.Results?

        if let prf {
            do throws(CTAP2.SessionError) {
                prfOutput = try prf.getAssertion.output(from: response)
            } catch {
                throw WebAuthn.Error(error)
            }
        }

        let credBlob = response.authenticatorData.extensions?[.credBlob]?.dataValue

        return WebAuthn.Extension.AuthenticationOutputs(
            prf: prfOutput,
            credBlob: credBlob,
            largeBlob: largeBlobOutput
        )
    }

    // MARK: - Large Blob Processing

    func processLargeBlob(
        from response: CTAP2.GetAssertion.Response,
        action: WebAuthn.Extension.LargeBlob.AuthenticationInput?,
        token: CTAP2.Token?
    ) async throws(WebAuthn.Error) -> WebAuthn.Extension.LargeBlob.AuthenticationOutput? {
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
                throw WebAuthn.Error(error)
            }
        }
    }
}
