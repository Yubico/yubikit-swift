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

// MARK: - Credential Matching

extension WebAuthn.Client {

    // Silently probes authenticator to find a matching credential from the list.
    // Used for exclude list (registration) and allow list (authentication) checks.
    // Handles authenticator limits by filtering long IDs and chunking requests.
    func findMatchingCredential(
        from credentials: [WebAuthn.CredentialDescriptor],
        rpId: String,
        cachedInfo: CTAP2.GetInfo.ImmutableView,
        token: CTAP2.Token?
    ) async throws(WebAuthn.ClientError) -> WebAuthn.CredentialDescriptor? {
        guard !credentials.isEmpty else { return nil }

        // Filter by type (only "public-key" is valid per WebAuthn spec).
        // Filter out IDs exceeding max length.
        let maxLength = cachedInfo.maxCredentialIdLength.map { Int($0) }
        var filtered = credentials.filter { cred in
            guard cred.type == "public-key" else { return false }
            guard let maxLength else { return true }
            return cred.id.count <= maxLength
        }
        guard !filtered.isEmpty else { return nil }

        var maxChunkSize = cachedInfo.maxCredentialCountInList.map { Int($0) } ?? 1
        let dummyClientDataHash = Data(repeating: 0, count: 32)

        // Process in chunks, reducing size on requestTooLarge.
        while !filtered.isEmpty && maxChunkSize > 0 {
            let chunkSize = min(maxChunkSize, filtered.count)
            let chunk = Array(filtered.prefix(chunkSize))

            // Silent probe (up=false).
            let parameters = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: dummyClientDataHash,
                allowList: chunk.map { .init(id: $0.id) },
                extensions: [],
                up: false
            )

            do throws(CTAP2.SessionError) {
                let response = try await backend.getAssertion(parameters: parameters, token: token).value
                if chunk.count == 1 { return chunk[0] }
                if let credentialId = response.credential?.id {
                    return WebAuthn.CredentialDescriptor(id: credentialId)
                }
                throw .responseParseError(
                    "Expecting credential ID in response when allowList has multiple credentials",
                    source: .here()
                )
            } catch {
                switch error {
                case .ctapError(.noCredentials, _):
                    filtered.removeFirst(chunkSize)
                case .ctapError(.requestTooLarge, _) where maxChunkSize > 1:
                    maxChunkSize -= 1
                default:
                    throw WebAuthn.ClientError(error)
                }
            }
        }

        return nil
    }
}
