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

import CryptoKit
import Foundation
import Testing

@_spi(YubiInternal) @testable import YubiKit

/// The two ceremonies over a `WebAuthn.DelegatedAuthenticator`, against a fake.
///
/// The point of these is the seam, not the crypto: what the client resolves before delegating, and
/// what it assembles from the raw output afterwards.
@Suite("Delegated ceremonies")
struct DelegatedCeremonyTests {

    // MARK: - Registration

    @Test("Registration assembles a response from the authenticator's raw output")
    func registrationAssemblesResponse() async throws {
        let authenticator = FakeDelegatedAuthenticator()

        let response = try await client(authenticator).makeCredential(
            Fixture.registrationOptions(),
            authorization: .uvOnly
        ).value

        #expect(response.credentialId == Fixture.credentialId)
        #expect(response.signCount == 0)
        #expect(response.aaguid.rawValue == Data(repeating: 0, count: 16))
        // fmt "none": the client assembles it, the authenticator never encodes CBOR.
        if case .none = response.attestationStatement {
        } else {
            Issue.record("Expected an unattested statement, got \(response.attestationStatement)")
        }
        #expect(!response.rawAttestationObject.isEmpty)
    }

    @Test("The authenticator receives the resolved rp id and the client data hash")
    func registrationDelegatesResolvedInputs() async throws {
        let authenticator = FakeDelegatedAuthenticator()

        _ = try await client(authenticator).makeCredential(
            Fixture.registrationOptions(),
            authorization: .uvOnly
        ).value

        let call = try #require(await authenticator.lastMakeCredential)
        #expect(call.rpId == Fixture.rpId)
        #expect(call.userHandle == Fixture.userHandle)
        #expect(call.pubKeyCredParams == [.es256])
        let expected = WebAuthn.ClientData.webauthn(
            type: "webauthn.create",
            challenge: Fixture.challenge,
            origin: Fixture.origin,
            rpId: Fixture.rpId
        )
        #expect(call.clientDataHash == expected.clientDataHash)
    }

    @Test("Attachment is the authenticator's to report, not the client's to assume")
    func attachmentComesFromTheAuthenticator() async throws {
        for attachment in [WebAuthn.AuthenticatorAttachment.platform, .crossPlatform] {
            let authenticator = FakeDelegatedAuthenticator(attachment: attachment)

            let response = try await client(authenticator).makeCredential(
                Fixture.registrationOptions(),
                authorization: .uvOnly
            ).value

            #expect(response.authenticatorAttachment == attachment)
            // Only a device-bound credential is reached internally.
            #expect(response.transports == (attachment == .platform ? [.internal] : []))
        }
    }

    @Test("credProps reports what the authenticator did, and only when asked")
    func credPropsReflectsTheAuthenticator() async throws {
        let discoverable = FakeDelegatedAuthenticator(isDiscoverable: true)
        let serverSide = FakeDelegatedAuthenticator(isDiscoverable: false)

        let asked = try await client(discoverable).makeCredential(
            Fixture.registrationOptions(credProps: true),
            authorization: .uvOnly
        ).value
        #expect(asked.clientExtensionResults.credProps?.rk == true)

        // `residentKey: .required` in the request must not be mistaken for an outcome.
        let contradicted = try await client(serverSide).makeCredential(
            Fixture.registrationOptions(credProps: true, residentKey: .required),
            authorization: .uvOnly
        ).value
        #expect(contradicted.clientExtensionResults.credProps?.rk == false)

        let notAsked = try await client(discoverable).makeCredential(
            Fixture.registrationOptions(),
            authorization: .uvOnly
        ).value
        #expect(notAsked.clientExtensionResults.credProps == nil)
    }

    @Test("Only public-key descriptors reach the exclude list")
    func excludeListIsFiltered() async throws {
        let authenticator = FakeDelegatedAuthenticator()
        let options = Fixture.registrationOptions(excludeCredentials: [
            WebAuthn.CredentialDescriptor(type: "public-key", id: Fixture.otherCredentialId),
            WebAuthn.CredentialDescriptor(type: "not-a-key", id: Data([0xFF])),
        ])

        _ = try await client(authenticator).makeCredential(options, authorization: .uvOnly).value

        #expect(await authenticator.lastMakeCredential?.excludeCredentialIds == [Fixture.otherCredentialId])
    }

    @Test("An rp id outside the origin is refused before the authenticator is touched")
    func registrationValidatesRpId() async throws {
        let authenticator = FakeDelegatedAuthenticator()
        let guarded = WebAuthn.Client(
            authenticator: authenticator,
            origin: try WebAuthn.Origin("https://evil.example"),
            isPublicSuffix: { _ in false }
        )

        await #expect(throws: WebAuthn.ClientError.self) {
            try await guarded.makeCredential(Fixture.registrationOptions(), authorization: .uvOnly).value
        }
        #expect(await authenticator.lastMakeCredential == nil)
    }

    @Test("Unparseable authenticator data fails the ceremony rather than the process")
    func registrationRejectsGarbage() async throws {
        let authenticator = FakeDelegatedAuthenticator(authenticatorData: Data([0x00, 0x01]))

        await #expect(throws: WebAuthn.ClientError.self) {
            try await client(authenticator).makeCredential(
                Fixture.registrationOptions(),
                authorization: .uvOnly
            ).value
        }
    }

    // MARK: - Authentication

    @Test("An empty allow list returns one response per discoverable credential")
    func discoverableReturnsEveryMatch() async throws {
        let authenticator = FakeDelegatedAuthenticator(
            stored: [
                Fixture.storedCredential(Fixture.credentialId), Fixture.storedCredential(Fixture.otherCredentialId),
            ]
        )

        let responses = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(),
            authorization: .uvOnly
        ).value

        #expect(responses.map(\.credentialId) == [Fixture.credentialId, Fixture.otherCredentialId])
        #expect(await authenticator.lastGetAssertions?.rpId == Fixture.rpId)
    }

    @Test("A non-empty allow list narrows to one credential, in the relying party's order")
    func allowListNarrowsToOne() async throws {
        let authenticator = FakeDelegatedAuthenticator(
            stored: [
                Fixture.storedCredential(Fixture.credentialId), Fixture.storedCredential(Fixture.otherCredentialId),
            ]
        )
        let options = Fixture.authenticationOptions(allowCredentials: [
            WebAuthn.CredentialDescriptor(id: Fixture.otherCredentialId)
        ])

        let responses = try await client(authenticator).getAssertion(options, authorization: .uvOnly).value

        #expect(responses.map(\.credentialId) == [Fixture.otherCredentialId])
        #expect(await authenticator.lastGetAssertions?.credentialIds == [Fixture.otherCredentialId])
    }

    @Test("An unmatched allow list still reaches the authenticator before reporting noCredentials")
    func unmatchedAllowListStillVerifies() async throws {
        let authenticator = FakeDelegatedAuthenticator(stored: [Fixture.storedCredential(Fixture.credentialId)])
        let options = Fixture.authenticationOptions(allowCredentials: [
            WebAuthn.CredentialDescriptor(id: Data([0xAB, 0xCD]))
        ])

        await #expect(throws: WebAuthn.ClientError.self) {
            try await client(authenticator).getAssertion(options, authorization: .uvOnly).value
        }
        // The empty selection is passed through on purpose: refusing locally would be faster than
        // a real ceremony and would leak whether the credential exists.
        #expect(await authenticator.lastGetAssertions?.credentialIds == [])
    }

    @Test("An empty user handle is reported as no user rather than an empty one")
    func emptyUserHandleBecomesNil() async throws {
        let authenticator = FakeDelegatedAuthenticator(
            stored: [Fixture.storedCredential(Fixture.credentialId)],
            userHandle: nil
        )

        let responses = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(),
            authorization: .uvOnly
        ).value

        #expect(responses.first?.user == nil)
    }

    @Test("An omitted rp id falls back to the origin's host")
    func omittedRpIdFallsBackToOrigin() async throws {
        let authenticator = FakeDelegatedAuthenticator(stored: [Fixture.storedCredential(Fixture.credentialId)])

        _ = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(rpId: nil),
            authorization: .uvOnly
        ).value

        #expect(await authenticator.lastGetAssertions?.rpId == Fixture.rpId)
        #expect(await authenticator.listCredentialsCalls == [Fixture.rpId])
    }

    @Test("Assertion responses carry the authenticator's attachment")
    func assertionAttachment() async throws {
        let authenticator = FakeDelegatedAuthenticator(
            stored: [Fixture.storedCredential(Fixture.credentialId)],
            attachment: .crossPlatform
        )

        let responses = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(),
            authorization: .uvOnly
        ).value

        #expect(responses.first?.authenticatorAttachment == .crossPlatform)
    }

    // MARK: - Support

    private func client(_ authenticator: any WebAuthn.DelegatedAuthenticator) -> WebAuthn.Client {
        WebAuthn.Client(
            authenticator: authenticator,
            origin: Fixture.origin,
            isPublicSuffix: { _ in false }
        )
    }
}

// MARK: - Fake

private actor FakeDelegatedAuthenticator: WebAuthn.DelegatedAuthenticator {

    struct MakeCredentialCall: Equatable {
        let rpId: String
        let userHandle: Data
        let userName: String?
        let clientDataHash: Data
        let pubKeyCredParams: [COSE.Algorithm]
        let excludeCredentialIds: [Data]
    }

    struct GetAssertionsCall: Equatable {
        let credentialIds: [Data]
        let rpId: String
        let clientDataHash: Data
    }

    nonisolated let attachment: WebAuthn.AuthenticatorAttachment

    private let stored: [WebAuthn.AuthenticatorCredential]
    private let isDiscoverable: Bool
    private let authenticatorData: Data
    private let userHandle: Data?

    private(set) var lastMakeCredential: MakeCredentialCall?
    private(set) var lastGetAssertions: GetAssertionsCall?
    private(set) var listCredentialsCalls: [String?] = []

    init(
        stored: [WebAuthn.AuthenticatorCredential] = [],
        attachment: WebAuthn.AuthenticatorAttachment = .platform,
        isDiscoverable: Bool = true,
        authenticatorData: Data = Fixture.registrationAuthenticatorData,
        userHandle: Data? = Fixture.userHandle
    ) {
        self.stored = stored
        self.attachment = attachment
        self.isDiscoverable = isDiscoverable
        self.authenticatorData = authenticatorData
        self.userHandle = userHandle
    }

    func makeCredential(
        rpId: String,
        userHandle: Data,
        userName: String?,
        clientDataHash: Data,
        pubKeyCredParams: [COSE.Algorithm],
        excludeCredentialIds: [Data]
    ) async throws(WebAuthn.ClientError) -> WebAuthn.AuthenticatorRegistration {
        lastMakeCredential = MakeCredentialCall(
            rpId: rpId,
            userHandle: userHandle,
            userName: userName,
            clientDataHash: clientDataHash,
            pubKeyCredParams: pubKeyCredParams,
            excludeCredentialIds: excludeCredentialIds
        )
        return WebAuthn.AuthenticatorRegistration(
            authenticatorData: authenticatorData,
            isDiscoverable: isDiscoverable
        )
    }

    func getAssertions(
        credentialIds: [Data],
        rpId: String,
        clientDataHash: Data
    ) async throws(WebAuthn.ClientError) -> [WebAuthn.AuthenticatorAssertion] {
        lastGetAssertions = GetAssertionsCall(
            credentialIds: credentialIds,
            rpId: rpId,
            clientDataHash: clientDataHash
        )
        guard !credentialIds.isEmpty else { throw .noCredentials(source: .here()) }
        // Echoed rather than fixed, so a test asserting on `credentialId` is seeing what the
        // client selected rather than a constant.
        return credentialIds.map {
            WebAuthn.AuthenticatorAssertion(
                credentialId: $0,
                userHandle: userHandle,
                signature: Fixture.signature,
                authenticatorData: Fixture.assertionAuthenticatorData
            )
        }
    }

    func listCredentials(rpId: String?) async throws(WebAuthn.ClientError) -> [WebAuthn.AuthenticatorCredential] {
        listCredentialsCalls.append(rpId)
        guard let rpId else { return stored }
        return stored.filter { $0.rpId == rpId }
    }
}

// MARK: - Fixtures

private enum Fixture {

    static let rpId = "example.com"
    static let origin = try! WebAuthn.Origin("https://example.com")
    static let credentialId = Data(repeating: 0xA1, count: 16)
    static let otherCredentialId = Data(repeating: 0xB2, count: 16)
    static let userHandle = Data(repeating: 0xC3, count: 8)
    static let challenge = Data(repeating: 0xD4, count: 32)
    static let signature = Data(repeating: 0xE5, count: 64)

    static func storedCredential(_ id: Data) -> WebAuthn.AuthenticatorCredential {
        WebAuthn.AuthenticatorCredential(id: id, rpId: rpId, userName: "alice@example.com")
    }

    static func registrationOptions(
        credProps: Bool = false,
        residentKey: WebAuthn.ResidentKeyPreference = .preferred,
        excludeCredentials: [WebAuthn.CredentialDescriptor] = []
    ) -> WebAuthn.Registration.Options {
        WebAuthn.Registration.Options(
            challenge: challenge,
            rp: WebAuthn.RelyingParty(id: rpId, name: "Example"),
            user: WebAuthn.User(id: userHandle, name: "alice@example.com"),
            excludeCredentials: excludeCredentials,
            residentKey: residentKey,
            pubKeyCredParams: [.es256],
            extensions: credProps ? WebAuthn.Extension.RegistrationInputs(credProps: true) : nil
        )
    }

    static func authenticationOptions(
        rpId: String? = Fixture.rpId,
        allowCredentials: [WebAuthn.CredentialDescriptor] = []
    ) -> WebAuthn.Authentication.Options {
        WebAuthn.Authentication.Options(
            challenge: challenge,
            rpId: rpId,
            allowCredentials: allowCredentials
        )
    }

    /// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` — an ES256 COSE key in CTAP2 canonical order.
    private static let coseKey =
        Data([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        + Data(repeating: 0x11, count: 32)
        + Data([0x22, 0x58, 0x20])
        + Data(repeating: 0x33, count: 32)

    /// UP | UV | AT, then `aaguid || credentialIdLength || credentialId || coseKey`.
    static let registrationAuthenticatorData =
        Data(SHA256.hash(data: Data(rpId.utf8)))
        + Data([0x45, 0, 0, 0, 0])
        + Data(repeating: 0, count: 16)
        + Data([0, UInt8(credentialId.count)])
        + credentialId
        + coseKey

    /// UP | UV, and no attested credential data — an assertion attests no key.
    static let assertionAuthenticatorData =
        Data(SHA256.hash(data: Data(rpId.utf8))) + Data([0x05, 0, 0, 0, 1])
}
