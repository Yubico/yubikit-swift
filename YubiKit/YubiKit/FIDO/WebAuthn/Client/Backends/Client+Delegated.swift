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

/*
 * The two ceremonies over a `WebAuthn.DelegatedAuthenticator`.
 *
 * The entry points in Client+MakeCredential and Client+GetAssertion route here after they have
 * validated the RP ID and built the client data, so everything above the authenticator is shared
 * with the CTAP2 path. What is left is the part that differs, and it is mostly what is *absent*:
 * no capability discovery, no PIN/UV token, no silent probing, no assertion paging, and no
 * extension processing beyond credProps.
 *
 * Both ceremonies yield nothing on the status stream before the result. A delegated authenticator
 * verifies the user inside its own call, so there is no touch or PIN step for the client to report.
 */

// MARK: - Registration

extension WebAuthn.Client {

    func performDelegatedMakeCredential(
        authenticator: any WebAuthn.DelegatedAuthenticator,
        options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData
    ) async throws(WebAuthn.ClientError) -> WebAuthn.Registration.Response {

        let registration = try await authenticator.makeCredential(
            rpId: clientData.rpId,
            userHandle: options.user.id,
            userName: options.user.name,
            clientDataHash: clientData.clientDataHash,
            pubKeyCredParams: options.pubKeyCredParams,
            // The authenticator applies the exclude list itself, after verifying the user. The
            // CTAP2 path probes silently first because it can; here that would mean a second
            // round trip revealing credential presence before verification.
            excludeCredentialIds: options.excludeCredentials
                .filter { $0.type == "public-key" }
                .map(\.id)
        )

        guard let authenticatorData = WebAuthn.AuthenticatorData(data: registration.authenticatorData) else {
            throw .internalError("Could not parse the delegated authenticator data", source: .here())
        }
        guard let attested = authenticatorData.attestedCredentialData else {
            throw .internalError(
                "Delegated authenticator data carried no attested credential data",
                source: .here()
            )
        }

        // A delegated authenticator does not attest. `fmt: "none"` with an empty statement is what
        // the spec asks for, and the client assembles it so a conformer never encodes CBOR.
        let attestationObject = WebAuthn.AttestationObject(
            format: "none",
            statementCBOR: [CBOR.Value: CBOR.Value]().cbor(),
            authenticatorData: authenticatorData
        )

        return WebAuthn.Registration.Response(
            credentialId: attested.credentialId,
            rawAttestationObject: attestationObject.rawData,
            rawAuthenticatorData: authenticatorData.rawData,
            attestationStatement: attestationObject.statement,
            transports: transports(for: authenticator),
            clientExtensionResults: .init(credProps: credProps(options, registration)),
            publicKey: attested.credentialPublicKey,
            aaguid: attested.aaguid,
            signCount: authenticatorData.signCount,
            authenticatorAttachment: authenticator.attachment,
            authenticatorData: authenticatorData,
            clientDataJSON: clientData.clientDataJSON
        )
    }

    // Absent unless the relying party asked for it; the value is the authenticator's, since
    // `options.residentKey` is a preference and only the authenticator knows what it did with it.
    private func credProps(
        _ options: WebAuthn.Registration.Options,
        _ registration: WebAuthn.AuthenticatorRegistration
    ) -> WebAuthn.Extension.CredProps.Registration.Output? {
        guard options.extensions?.credProps == true else { return nil }
        return .init(rk: registration.isDiscoverable)
    }

    // A delegated authenticator reports no transport hints of its own, so the attachment is all
    // the client can honestly say: device-bound credentials are reached internally.
    private func transports(
        for authenticator: any WebAuthn.DelegatedAuthenticator
    ) -> [WebAuthn.Transport] {
        authenticator.attachment == .platform ? [.internal] : []
    }
}

// MARK: - Authentication

extension WebAuthn.Client {

    func performDelegatedGetAssertions(
        authenticator: any WebAuthn.DelegatedAuthenticator,
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData
    ) async throws(WebAuthn.ClientError) -> [WebAuthn.Authentication.Response] {

        let rpId = clientData.rpId
        let stored = try await authenticator.listCredentials(rpId: rpId)
        let selected = select(from: options.allowCredentials, in: stored)

        // An empty selection is passed through deliberately. The authenticator must still verify
        // the user before reporting `.noCredentials`, for the same reason the CTAP2 path sends a
        // dummy credential: otherwise the refusal is faster than a real ceremony and leaks whether
        // a credential is present.
        let assertions = try await authenticator.getAssertions(
            credentialIds: selected,
            rpId: rpId,
            clientDataHash: clientData.clientDataHash
        )
        guard !assertions.isEmpty else { throw .noCredentials(source: .here()) }

        var responses: [WebAuthn.Authentication.Response] = []
        responses.reserveCapacity(assertions.count)
        for assertion in assertions {
            guard let authenticatorData = WebAuthn.AuthenticatorData(data: assertion.authenticatorData) else {
                throw .internalError("Could not parse the delegated authenticator data", source: .here())
            }
            responses.append(
                WebAuthn.Authentication.Response(
                    credentialId: assertion.credentialId,
                    rawAuthenticatorData: authenticatorData.rawData,
                    signature: assertion.signature,
                    user: assertion.userHandle.map { WebAuthn.User(id: $0) },
                    clientExtensionResults: .empty,
                    signCount: authenticatorData.signCount,
                    authenticatorAttachment: authenticator.attachment,
                    authenticatorData: authenticatorData,
                    clientDataJSON: clientData.clientDataJSON
                )
            )
        }
        return responses
    }

    // Narrows the stored credentials to those the request allows.
    //
    // An empty allow list is the discoverable flow and selects everything held for the relying
    // party — the caller picks among the assertions afterwards, which is where the CTAP2 path's
    // `getNextAssertion` paging lands too. A non-empty list selects at most one, in the relying
    // party's order of preference rather than storage order.
    private func select(
        from allowCredentials: [WebAuthn.CredentialDescriptor],
        in stored: [WebAuthn.AuthenticatorCredential]
    ) -> [Data] {
        guard !allowCredentials.isEmpty else { return stored.map(\.id) }
        for allowed in allowCredentials where allowed.type == "public-key" {
            if stored.contains(where: { $0.id == allowed.id }) { return [allowed.id] }
        }
        return []
    }
}
