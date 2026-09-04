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

@Suite("Authenticator backend")
struct AuthenticatorBackendTests {

    @Test("Registration forwards ceremony inputs, policy, progress, and the backend response")
    func registrationContract() async throws {
        let authenticator = FakeAuthenticatorBackend()
        let client = client(authenticator)
        let options = Fixture.registrationOptions()
        var progress = 0
        var finished = 0
        for try await status in await client.makeCredential(options, authorization: .pin("1234")) {
            switch status {
            case .processing:
                progress += 1
            case .finished(let response):
                finished += 1
                #expect(response.credentialId == Fixture.credentialId)
                #expect(response.authenticatorAttachment == .crossPlatform)
                #expect(response.transports == [.usb])
                #expect(response.clientExtensionResults.credProps?.rk == false)
            default:
                Issue.record("Unexpected status")
            }
        }
        #expect(progress == 1)
        #expect(finished == 1)
        let call = try #require(await authenticator.registration)
        #expect(call.options.user.id == options.user.id)
        #expect(call.options.excludeCredentials == options.excludeCredentials)
        #expect(call.options.residentKey == options.residentKey)
        #expect(call.options.pubKeyCredParams == options.pubKeyCredParams)
        #expect(call.enterpriseRpIds == [Fixture.rpId])
        #expect(call.allowedExtensions == [.credProps])
        #expect(call.clientData.clientDataHash == Fixture.clientData("webauthn.create").clientDataHash)
        guard case .pin("1234") = await call.authorization.providePIN() else {
            Issue.record("Authorization callback was not forwarded")
            return
        }
    }

    @Test("Authentication forwards full options and preserves backend response order")
    func authenticationContract() async throws {
        let authenticator = FakeAuthenticatorBackend()
        let options = Fixture.authenticationOptions()
        var progress = 0
        var finished = 0
        for try await status in await client(authenticator).getAssertion(options, authorization: .pin("5678")) {
            switch status {
            case .processing:
                progress += 1
            case .finished(let responses):
                finished += 1
                #expect(responses.map(\.credentialId) == [Fixture.credentialId, Fixture.otherCredentialId])
                #expect(responses.allSatisfy { $0.authenticatorAttachment == .crossPlatform })
            default:
                Issue.record("Unexpected status")
            }
        }
        #expect(progress == 1)
        #expect(finished == 1)
        let call = try #require(await authenticator.authentication)
        #expect(call.options.allowCredentials == options.allowCredentials)
        #expect(call.allowedExtensions == [.credProps])
        #expect(call.clientData.rpId == Fixture.rpId)
        #expect(call.clientData.clientDataHash == Fixture.clientData("webauthn.get").clientDataHash)
        guard case .pin("5678") = await call.authorization.providePIN() else {
            Issue.record("Authorization callback was not forwarded")
            return
        }
    }

    @Test("Both ceremonies validate the RP ID before invoking the backend")
    func validatesRpId() async throws {
        let authenticator = FakeAuthenticatorBackend()
        let guarded = WebAuthn.Client(
            authenticator: authenticator,
            origin: try WebAuthn.Origin("https://evil.example"),
            isPublicSuffix: { _ in false }
        )
        await #expect(throws: WebAuthn.ClientError.self) {
            try await guarded.makeCredential(Fixture.registrationOptions(), authorization: .uvOnly).value
        }
        await #expect(throws: WebAuthn.ClientError.self) {
            try await guarded.getAssertion(
                .init(challenge: Fixture.challenge, rpId: Fixture.rpId), authorization: .uvOnly
            ).value
        }
        #expect(await authenticator.registration == nil)
        #expect(await authenticator.authentication == nil)
    }

    @Test("Custom client data is forwarded without rebuilding it")
    func customClientData() async throws {
        let authenticator = FakeAuthenticatorBackend()
        let data = WebAuthn.ClientData.hash(
            Data(repeating: 0x91, count: 32), origin: Fixture.origin, rpId: Fixture.rpId
        )
        _ = try await client(authenticator).makeCredential(
            Fixture.registrationOptions(), clientData: data, authorization: .uvOnly
        ).value
        _ = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(), clientData: data, authorization: .uvOnly
        ).value
        #expect(await authenticator.registration?.clientData.clientDataHash == data.clientDataHash)
        #expect(await authenticator.authentication?.clientData.clientDataHash == data.clientDataHash)
        #expect(await authenticator.registration?.clientData.clientDataJSON == nil)
    }

    @Test("Both ceremonies preserve backend errors")
    func preservesErrors() async throws {
        let authenticator = FakeAuthenticatorBackend(error: .cancelled(source: .here()))
        do {
            _ = try await client(authenticator).makeCredential(
                Fixture.registrationOptions(), authorization: .uvOnly
            ).value
            Issue.record("Expected cancellation")
        } catch {
            guard case WebAuthn.ClientError.cancelled = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        }
        do {
            _ = try await client(authenticator).getAssertion(
                Fixture.authenticationOptions(), authorization: .uvOnly
            ).value
            Issue.record("Expected cancellation")
        } catch {
            guard case WebAuthn.ClientError.cancelled = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        }
    }

    @Test("Backend-owned ceremonies can outlive the requested timeout")
    func ignoresTimeout() async throws {
        let authenticator = FakeAuthenticatorBackend(responseDelay: .milliseconds(30))
        _ = try await client(authenticator).makeCredential(
            Fixture.registrationOptions(timeout: .milliseconds(1)), authorization: .uvOnly
        ).value
        _ = try await client(authenticator).getAssertion(
            Fixture.authenticationOptions(timeout: .milliseconds(1)), authorization: .uvOnly
        ).value
    }

    private func client(_ authenticator: any WebAuthn.AuthenticatorBackend) -> WebAuthn.Client {
        WebAuthn.Client(
            authenticator: authenticator,
            origin: Fixture.origin,
            enterpriseRpIds: [Fixture.rpId],
            allowedExtensions: [.credProps],
            isPublicSuffix: { _ in false }
        )
    }
}

private actor FakeAuthenticatorBackend: WebAuthn.AuthenticatorBackend {
    struct RegistrationCall {
        let options: WebAuthn.Registration.Options
        let clientData: WebAuthn.ClientData
        let authorization: WebAuthn.Authorization
        let enterpriseRpIds: Set<String>
        let allowedExtensions: Set<WebAuthn.Extension.Identifier>
    }

    struct AuthenticationCall {
        let options: WebAuthn.Authentication.Options
        let clientData: WebAuthn.ClientData
        let authorization: WebAuthn.Authorization
        let allowedExtensions: Set<WebAuthn.Extension.Identifier>
    }

    private(set) var registration: RegistrationCall?
    private(set) var authentication: AuthenticationCall?
    private let responseDelay: Duration?
    private let error: WebAuthn.ClientError?
    init(responseDelay: Duration? = nil, error: WebAuthn.ClientError? = nil) {
        self.responseDelay = responseDelay
        self.error = error
    }

    func makeCredential(
        options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        enterpriseRpIds: Set<String>,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        registration = .init(
            options: options, clientData: clientData, authorization: authorization,
            enterpriseRpIds: enterpriseRpIds, allowedExtensions: allowedExtensions
        )
        return WebAuthn.StatusStream { [responseDelay, error] continuation in
            Task {
                continuation.yield(.processing)
                if let responseDelay { try? await Task.sleep(for: responseDelay) }
                if let error {
                    continuation.yield(error: error)
                } else {
                    continuation.yield(.finished(Fixture.registrationResponse(clientData)))
                }
            }
        }
    }

    func getAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        authentication = .init(
            options: options, clientData: clientData, authorization: authorization,
            allowedExtensions: allowedExtensions
        )
        return WebAuthn.StatusStream { [responseDelay, error] continuation in
            Task {
                continuation.yield(.processing)
                if let responseDelay { try? await Task.sleep(for: responseDelay) }
                if let error {
                    continuation.yield(error: error)
                } else {
                    let responses = [Fixture.credentialId, Fixture.otherCredentialId].map {
                        Fixture.assertionResponse($0, clientData)
                    }
                    continuation.yield(.finished(responses))
                }
            }
        }
    }
}

private enum Fixture {
    static let rpId = "example.com"
    static let origin = try! WebAuthn.Origin("https://example.com")
    static let credentialId = Data(repeating: 0xA1, count: 16)
    static let otherCredentialId = Data(repeating: 0xB2, count: 16)
    static let userHandle = Data(repeating: 0xC3, count: 8)
    static let challenge = Data(repeating: 0xD4, count: 32)

    static func clientData(_ type: String) -> WebAuthn.ClientData {
        .webauthn(type: type, challenge: challenge, origin: origin, rpId: rpId)
    }

    static func registrationOptions(timeout: Duration? = nil) -> WebAuthn.Registration.Options {
        .init(
            challenge: challenge,
            rp: .init(id: rpId, name: "Example"),
            user: .init(id: userHandle, name: "alice@example.com"),
            excludeCredentials: [.init(id: otherCredentialId)],
            residentKey: .required,
            pubKeyCredParams: [.es256],
            timeout: timeout,
            extensions: .init(credProps: true)
        )
    }

    static func authenticationOptions(timeout: Duration? = nil) -> WebAuthn.Authentication.Options {
        .init(
            challenge: challenge,
            allowCredentials: [.init(id: otherCredentialId), .init(id: credentialId)],
            timeout: timeout
        )
    }

    static func registrationResponse(_ clientData: WebAuthn.ClientData) -> WebAuthn.Registration.Response {
        let data = WebAuthn.AuthenticatorData(data: registrationAuthenticatorData)!
        let attested = data.attestedCredentialData!
        let object = WebAuthn.AttestationObject(
            format: "none", statementCBOR: [CBOR.Value: CBOR.Value]().cbor(), authenticatorData: data
        )
        return .init(
            credentialId: credentialId, rawAttestationObject: object.rawData,
            rawAuthenticatorData: data.rawData, attestationStatement: object.statement,
            transports: [.usb], clientExtensionResults: .init(credProps: .init(rk: false)),
            publicKey: attested.credentialPublicKey, aaguid: attested.aaguid, signCount: data.signCount,
            authenticatorAttachment: .crossPlatform, authenticatorData: data,
            clientDataJSON: clientData.clientDataJSON
        )
    }

    static func assertionResponse(
        _ id: Data, _ clientData: WebAuthn.ClientData
    ) -> WebAuthn.Authentication.Response {
        let raw = Data(SHA256.hash(data: Data(rpId.utf8))) + Data([0x05, 0, 0, 0, 1])
        let data = WebAuthn.AuthenticatorData(data: raw)!
        return .init(
            credentialId: id, rawAuthenticatorData: raw, signature: Data(repeating: 0xE5, count: 64),
            user: .init(id: userHandle), clientExtensionResults: .empty, signCount: data.signCount,
            authenticatorAttachment: .crossPlatform, authenticatorData: data,
            clientDataJSON: clientData.clientDataJSON
        )
    }

    private static let coseKey =
        Data([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        + Data(repeating: 0x11, count: 32)
        + Data([0x22, 0x58, 0x20])
        + Data(repeating: 0x33, count: 32)

    private static let registrationAuthenticatorData =
        Data(SHA256.hash(data: Data(rpId.utf8)))
        + Data([0x45, 0, 0, 0, 0])
        + Data(repeating: 0, count: 16)
        + Data([0, UInt8(credentialId.count)])
        + credentialId
        + coseKey
}
