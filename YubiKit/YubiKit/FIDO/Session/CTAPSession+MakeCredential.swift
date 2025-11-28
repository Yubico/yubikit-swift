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

// MARK: - MakeCredential

extension CTAP2.Session {

    /// Create a new credential on the authenticator.
    ///
    /// This command registers a new FIDO2 credential with the authenticator. The authenticator
    /// will verify user presence (and optionally user verification via PIN/biometric), generate
    /// a new credential keypair, and return attestation data.
    ///
    /// > Important: This operation requires user interaction (touch) and may require PIN entry
    /// > if user verification is requested.
    ///
    /// > Note: This functionality requires support for ``CTAP/Feature/makeCredential``, available on YubiKey 5.0 or later.
    ///
    /// - Parameter parameters: The credential creation parameters.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorMakeCredential)
    func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        await interface.send(
            command: .makeCredential,
            payload: parameters
        )
    }

    /// Create a new credential with PIN authentication.
    func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        pin: String,
        pinProtocol: PinAuth.ProtocolVersion = .default
    ) async throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {

        var permissions: CTAP2.ClientPin.Permission = .makeCredential
        if let excludeList = parameters.excludeList, !excludeList.isEmpty {
            permissions.insert(.getAssertion)
        }

        let pinToken = try await getPinToken(
            pin: pin,
            permissions: permissions,
            rpId: parameters.rp.id,
            pinProtocol: pinProtocol
        )

        let pinUVAuthParam = pinProtocol.authenticate(
            key: pinToken,
            message: parameters.clientDataHash
        )

        let authenticatedParams = CTAP2.MakeCredential.Parameters(
            clientDataHash: parameters.clientDataHash,
            rp: parameters.rp,
            user: parameters.user,
            pubKeyCredParams: parameters.pubKeyCredParams,
            excludeList: parameters.excludeList,
            extensions: parameters.extensions,
            options: parameters.options,
            pinUVAuthParam: pinUVAuthParam,
            pinUVAuthProtocol: pinProtocol,
            enterpriseAttestation: parameters.enterpriseAttestation
        )

        return await interface.send(
            command: .makeCredential,
            payload: authenticatedParams
        )
    }
}
