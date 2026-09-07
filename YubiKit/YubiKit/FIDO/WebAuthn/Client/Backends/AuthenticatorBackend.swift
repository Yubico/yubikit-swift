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

extension WebAuthn {

    // Performs ceremonies after Client validates the RP ID and builds client data.
    // Implementations own credential selection, verification, extensions, and response assembly.
    // They also own progress, cancellation, and timeout handling; backends with their own
    // verification UX may ignore authorization.
    @_spi(YubiInternal)
    public protocol AuthenticatorBackend: Sendable {

        // Apply the exclude list without revealing credential presence before user interaction.
        func makeCredential(
            options: Registration.Options,
            clientData: ClientData,
            authorization: Authorization,
            enterpriseRpIds: Set<String>,
            allowedExtensions: Set<Extension.Identifier>
        ) async -> StatusStream<Registration.Response>

        // Honor the allow list and extension policy. Complete required user interaction before
        // reporting noCredentials, including when no credential matches the request.
        // A successful terminal result must contain at least one assertion.
        func getAssertions(
            options: Authentication.Options,
            clientData: ClientData,
            authorization: Authorization,
            allowedExtensions: Set<Extension.Identifier>
        ) async -> StatusStream<[Authentication.Response]>
    }
}
