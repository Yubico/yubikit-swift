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

    /// Create a new credential on the authenticator without authentication.
    ///
    /// Use this when no PIN/UV is required (e.g., user presence only).
    ///
    /// - Parameter parameters: The credential creation parameters.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        await interface.send(command: .makeCredential, payload: parameters)
    }

    /// Create a new credential using PIN authentication.
    ///
    /// > Important: Per CTAP 2.2 spec, platforms MUST NOT include both the `uv` option and
    /// > `pinUvAuthParam` in the same request. UV with PIN tokens must occur during token
    /// > acquisition via ``getPinToken(_:permissions:rpId:protocol:)``.
    ///
    /// - Parameters:
    ///   - parameters: The credential creation parameters.
    ///   - pinToken: PIN token obtained via ``getPinToken(_:permissions:rpId:protocol:)``.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        pinToken: CTAP2.ClientPin.PinToken
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        var params = parameters
        params.setAuthentication(pinToken)
        return await interface.send(command: .makeCredential, payload: params)
    }

    /// Create a new credential using biometric authentication.
    ///
    /// > Important: When using a UV token, user verification has already occurred during token
    /// > acquisition, so there is no `requireUserVerification` parameter.
    ///
    /// - Parameters:
    ///   - parameters: The credential creation parameters.
    ///   - uvToken: UV token obtained via ``getUVToken(permissions:rpId:protocol:)``.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        uvToken: CTAP2.ClientPin.UVToken
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        var params = parameters
        params.setAuthentication(uvToken)
        return await interface.send(command: .makeCredential, payload: params)
    }
}
