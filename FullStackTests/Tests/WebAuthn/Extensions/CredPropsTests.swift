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
import Testing

@testable import YubiKit

@Suite("WebAuthn CredProps Extension Tests", .serialized)
struct WebAuthnCredPropsExtensionTests {

    @Test("CredProps - Discoverable Credential Returns rk=true")
    func testCredPropsDiscoverable() async throws {
        try await withWebAuthnClient { client in
            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "example.com", name: "CredProps Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "credprops-rk@example.com",
                    displayName: "CredProps RK User"
                ),
                residentKey: .required,
                extensions: .init(credProps: true)
            )

            print("Making discoverable credential with credProps...")
            let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value

            #expect(response.clientExtensionResults.credProps != nil, "credProps should be present")
            #expect(response.clientExtensionResults.credProps?.rk == true, "rk should be true for discoverable")
            print("credProps.rk = \(response.clientExtensionResults.credProps?.rk ?? false)")
        }
    }

    @Test("CredProps - Non-Discoverable Credential Returns rk=false")
    func testCredPropsNonDiscoverable() async throws {
        try await withWebAuthnClient { client in
            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "example.com", name: "CredProps Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "credprops-nork@example.com",
                    displayName: "CredProps No RK User"
                ),
                residentKey: .discouraged,
                extensions: .init(credProps: true)
            )

            print("Making non-discoverable credential with credProps...")
            let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value

            #expect(response.clientExtensionResults.credProps != nil, "credProps should be present")
            #expect(response.clientExtensionResults.credProps?.rk == false, "rk should be false for non-discoverable")
            print("credProps.rk = \(response.clientExtensionResults.credProps?.rk ?? true)")
        }
    }

    @Test("CredProps - Not Requested Returns nil")
    func testCredPropsNotRequested() async throws {
        try await withWebAuthnClient { client in
            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "example.com", name: "CredProps Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "credprops-none@example.com",
                    displayName: "CredProps None User"
                ),
                residentKey: .required
            )

            print("Making credential without credProps extension...")
            let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value

            #expect(response.clientExtensionResults.credProps == nil, "credProps should be nil when not requested")
            print("credProps correctly nil")
        }
    }
}

// MARK: - Helpers

private func withWebAuthnClient<T>(
    _ body: (WebAuthn.Client) async throws -> T
) async throws -> T {
    try await withCTAP2Session { session in
        let client = WebAuthn.Client(
            session: session,
            origin: try WebAuthn.Origin("https://example.com"),
            allowedExtensions: [.credProps],
            isPublicSuffix: { _ in false }
        )
        return try await body(client)
    }
}
