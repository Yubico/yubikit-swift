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
    /// When a `token` is provided, the `uv` option is automatically cleared.
    ///
    /// - Parameters:
    ///   - parameters: The credential creation parameters.
    ///   - token: Optional PIN/UV auth token obtained via ``getPinUVToken(using:permissions:rpId:protocol:)``.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        token: CTAP2.Token? = nil
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        guard let token else {
            return await interface.send(command: .makeCredential, payload: parameters)
        }
        var params = parameters
        params.setAuthentication(token: token)
        return await interface.send(command: .makeCredential, payload: params)
    }
}
