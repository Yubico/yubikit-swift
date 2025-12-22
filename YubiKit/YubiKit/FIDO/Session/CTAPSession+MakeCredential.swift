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
    /// > Note: This functionality is available on YubiKey 5.0 or later.
    ///
    /// - Parameters:
    ///   - parameters: The credential creation parameters.
    ///   - pinToken: Optional PIN token for user verification. Obtain via ``getPinUVToken(using:permissions:rpId:protocol:)``.
    /// - Returns: AsyncSequence of status updates, ending with `.finished(response)` containing the credential data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        pinToken: CTAP2.ClientPin.Token? = nil
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {

        // If no PIN token provided, send parameters as-is
        guard let pinToken else {
            return await interface.send(
                command: .makeCredential,
                payload: parameters
            )
        }

        var authenticatedParams = parameters
        authenticatedParams.setAuthentication(pinToken: pinToken)

        return await interface.send(
            command: .makeCredential,
            payload: authenticatedParams
        )
    }
}
