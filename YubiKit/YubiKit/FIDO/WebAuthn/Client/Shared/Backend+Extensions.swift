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
        _ inputs: WebAuthn.Extension.RegistrationInputs?,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>,
        userVerification: WebAuthn.UserVerificationPreference = .preferred
    ) async throws(WebAuthn.ClientError) -> (
        ctapInputs: [CTAP2.Extension.MakeCredential.Input],
        prf: WebAuthn.Extension.PRF?,
        previewSign: CTAP2.Extension.PreviewSign?,
        largeBlobRequested: Bool
    ) {
        guard let inputs else {
            return ([], nil, nil, false)
        }

        var ctapInputs: [CTAP2.Extension.MakeCredential.Input] = []
        var prf: WebAuthn.Extension.PRF?
        var previewSign: CTAP2.Extension.PreviewSign?
        var largeBlobRequested = false

        do throws(CTAP2.SessionError) {
            if let prfInput = allowedExtensions.allow(.prf, inputs.prf) {
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

            if let credProtectInput = allowedExtensions.allow(.credProtect, inputs.credProtect) {
                let credProtect = try await makeCredProtect(
                    level: credProtectInput.policy,
                    enforce: credProtectInput.enforce
                )
                ctapInputs.append(credProtect.input())
            }

            if let credBlobData = allowedExtensions.allow(.credBlob, inputs.credBlob) {
                if let credBlob = try? await makeCredBlob() {
                    ctapInputs.append(try credBlob.makeCredential.input(blob: credBlobData))
                }
            }

            if let largeBlobInput = allowedExtensions.allow(.largeBlob, inputs.largeBlob) {
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

            if let previewSignInput = allowedExtensions.allow(.previewSign, inputs.previewSign) {
                if let ps = try? await makePreviewSign() {
                    let flags: UInt8 = userVerification == .required ? 0b101 : 0b001
                    ctapInputs.append(
                        ps.makeCredential.input(
                            algorithms: previewSignInput.algorithms,
                            flags: flags
                        )
                    )
                    previewSign = ps
                }
            }
        } catch {
            throw WebAuthn.ClientError(error)
        }

        if allowedExtensions.allow(.minPinLength, inputs.minPinLength) == true {
            do {
                if try await isMinPinLengthSupported() {
                    let minPinLength = try await makeMinPinLength()
                    ctapInputs.append(minPinLength.makeCredential.input())
                }
            } catch {
                // Ignore — minPinLength is best-effort.
            }
        }

        if let payment = allowedExtensions.allow(.thirdPartyPayment, inputs.thirdPartyPayment),
            payment.isPayment
        {
            if let ext = try? await makeThirdPartyPayment() {
                ctapInputs.append(ext.makeCredential.input())
            }
        }

        return (ctapInputs, prf, previewSign, largeBlobRequested)
    }

    // MARK: - GetAssertion Extensions

    func buildGetAssertionExtensions(
        _ inputs: WebAuthn.Extension.AuthenticationInputs?,
        allowCredentials: [WebAuthn.CredentialDescriptor],
        selectedCredentialId: Data?,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) async throws(WebAuthn.ClientError) -> (
        ctapInputs: [CTAP2.Extension.GetAssertion.Input],
        prf: WebAuthn.Extension.PRF?,
        previewSign: CTAP2.Extension.PreviewSign?,
        largeBlobAction: WebAuthn.Extension.LargeBlob.Authentication.Input?
    ) {
        guard let inputs else {
            return ([], nil, nil, nil)
        }

        var ctapInputs: [CTAP2.Extension.GetAssertion.Input] = []
        var prf: WebAuthn.Extension.PRF?
        var previewSign: CTAP2.Extension.PreviewSign?
        var largeBlobAction: WebAuthn.Extension.LargeBlob.Authentication.Input?

        if let prfInput = allowedExtensions.allow(.prf, inputs.prf) {
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

        if allowedExtensions.allow(.credBlob, inputs.getCredBlob) == true {
            if let credBlob = try? await makeCredBlob() {
                ctapInputs.append(credBlob.getAssertion.input())
            }
        }

        if let largeBlobInput = allowedExtensions.allow(.largeBlob, inputs.largeBlob) {
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

        if let previewSignInput = allowedExtensions.allow(.previewSign, inputs.previewSign) {
            if allowCredentials.isEmpty {
                throw .invalidRequest(
                    "sign requires allowCredentials",
                    source: .here()
                )
            }
            let allowedIds = Set(allowCredentials.map(\.id))
            guard allowedIds.isSubset(of: previewSignInput.signByCredential.keys) else {
                throw .invalidRequest(
                    "signByCredential not valid",
                    source: .here()
                )
            }

            if let ps = try? await makePreviewSign(), let selectedCredentialId {
                if let params = previewSignInput.signByCredential[selectedCredentialId] {
                    ctapInputs.append(
                        ps.getAssertion.input(
                            keyHandle: params.keyHandle,
                            tbs: params.tbs,
                            additionalArgs: params.additionalArgs
                        )
                    )
                    previewSign = ps
                }
            }
        }

        if let payment = allowedExtensions.allow(.thirdPartyPayment, inputs.thirdPartyPayment),
            payment.isPayment
        {
            if let ext = try? await makeThirdPartyPayment() {
                ctapInputs.append(ext.getAssertion.input())
            }
        }

        return (ctapInputs, prf, previewSign, largeBlobAction)
    }

    // MARK: - Output Parsing

    func parseRegistrationOutputs(
        from response: CTAP2.MakeCredential.Response,
        prf: WebAuthn.Extension.PRF?,
        previewSign: CTAP2.Extension.PreviewSign?,
        largeBlobRequested: Bool,
        credPropsRk: Bool?,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) throws(WebAuthn.ClientError) -> WebAuthn.Extension.RegistrationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.Registration.Output?

        if let prf = allowedExtensions.allow(.prf, prf) {
            do throws(CTAP2.SessionError) {
                if let ctapResult = try prf.makeCredential.output(from: response) {
                    prfOutput = .init(ctapResult: ctapResult)
                }
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }

        var previewSignOutput: WebAuthn.Extension.PreviewSign.Registration.Output?
        if let previewSign = allowedExtensions.allow(.previewSign, previewSign) {
            do throws(CTAP2.SessionError) {
                if let generatedKey = try previewSign.makeCredential.output(from: response) {
                    previewSignOutput = .init(generatedKey: generatedKey)
                }
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }

        let extensions = response.authenticatorData.extensions

        let credProtectOutput = allowedExtensions.allow(.credProtect, extensions?[.credProtect])
            .flatMap { WebAuthn.Extension.CredProtect.Policy(cbor: $0) }
            .map { WebAuthn.Extension.CredProtect.Registration.Output(policy: $0) }

        let credBlobOutput = allowedExtensions.allow(.credBlob, extensions?[.credBlob]?.boolValue)
            .map { WebAuthn.Extension.CredBlob.Registration.Output(stored: $0) }

        let minPinLengthOutput = allowedExtensions.allow(.minPinLength, extensions?[.minPinLength]?.uint64Value)
            .map { WebAuthn.Extension.MinPinLength.Registration.Output(length: UInt($0)) }

        let largeBlobOutput =
            allowedExtensions
            .allow(.largeBlob, largeBlobRequested ? response.largeBlobKey != nil : nil)
            .map { WebAuthn.Extension.LargeBlob.Registration.Output(supported: $0) }

        let credPropsOutput = allowedExtensions.allow(.credProps, credPropsRk)
            .map { WebAuthn.Extension.CredProps.Registration.Output(rk: $0) }

        let thirdPartyPaymentOutput =
            allowedExtensions
            .allow(.thirdPartyPayment, extensions?[.thirdPartyPayment]?.boolValue)
            .map { WebAuthn.Extension.ThirdPartyPayment.Registration.Output(isPaymentEnabled: $0) }

        return WebAuthn.Extension.RegistrationOutputs(
            prf: prfOutput,
            credProtect: credProtectOutput,
            credBlob: credBlobOutput,
            minPinLength: minPinLengthOutput,
            largeBlob: largeBlobOutput,
            credProps: credPropsOutput,
            previewSign: previewSignOutput,
            thirdPartyPayment: thirdPartyPaymentOutput
        )
    }

    func parseAuthenticationOutputs(
        from response: CTAP2.GetAssertion.Response,
        prf: WebAuthn.Extension.PRF?,
        previewSign: CTAP2.Extension.PreviewSign?,
        largeBlobOutput: WebAuthn.Extension.LargeBlob.Authentication.Output?,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) throws(WebAuthn.ClientError) -> WebAuthn.Extension.AuthenticationOutputs {
        var prfOutput: WebAuthn.Extension.PRF.Authentication.Output?

        if let prf = allowedExtensions.allow(.prf, prf) {
            do throws(CTAP2.SessionError) {
                if let ctapSecrets = try prf.getAssertion.output(from: response) {
                    prfOutput = .init(ctapSecrets: ctapSecrets)
                }
            } catch {
                throw WebAuthn.ClientError(error)
            }
        }

        let credBlobOutput =
            allowedExtensions
            .allow(.credBlob, response.authenticatorData.extensions?[.credBlob]?.dataValue)
            .map { WebAuthn.Extension.CredBlob.Authentication.Output(blob: $0) }

        var previewSignOutput: WebAuthn.Extension.PreviewSign.Authentication.Output?
        if let previewSign = allowedExtensions.allow(.previewSign, previewSign) {
            if let signature = previewSign.getAssertion.output(from: response) {
                previewSignOutput = .init(signature: signature)
            }
        }

        let thirdPartyPaymentOutput =
            allowedExtensions
            .allow(.thirdPartyPayment, response.authenticatorData.extensions?[.thirdPartyPayment]?.boolValue)
            .map { WebAuthn.Extension.ThirdPartyPayment.Authentication.Output(isPaymentEnabled: $0) }

        return WebAuthn.Extension.AuthenticationOutputs(
            prf: prfOutput,
            credBlob: credBlobOutput,
            largeBlob: allowedExtensions.allow(.largeBlob, largeBlobOutput),
            previewSign: previewSignOutput,
            thirdPartyPayment: thirdPartyPaymentOutput
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

extension Set where Element == WebAuthn.Extension.Identifier {
    fileprivate func allow<T>(_ id: Element, _ value: T?) -> T? {
        contains(id) ? value : nil
    }
}
