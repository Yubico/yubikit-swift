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

@Suite("WebAuthn UV Failure Tests", .serialized)
struct UVRetryTests {

    private static let options = WebAuthn.Authentication.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rpId: "example.com",
        userVerification: .required
    )

    // MARK: - One-shot UV with PIN Fallback

    @Test("uvInvalid falls back to PIN in same ceremony when clientPin configured")
    func testUVInvalidFallsBackToPIN() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 5 }

        var uvAttempts = 0
        var pinAttempts = 0
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                uvAttempts += 1
                throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
            case .pin(let pin):
                pinAttempts += 1
                #expect(pin == "1234")
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        let auth = WebAuthn.Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)
        var finished = false
        for try await status in stream {
            if case .finished = status { finished = true }
        }

        #expect(uvAttempts == 1)
        #expect(pinAttempts == 1)
        #expect(finished)
    }

    @Test("uvBlocked falls back to PIN in same ceremony when clientPin configured")
    func testUVBlockedFallsBackToPIN() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 3 }

        var uvAttempts = 0
        var pinAttempts = 0
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                uvAttempts += 1
                throw CTAP2.SessionError.ctapError(.uvBlocked, source: .here())
            case .pin(let pin):
                pinAttempts += 1
                #expect(pin == "1234")
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        let auth = WebAuthn.Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)
        var finished = false
        for try await status in stream {
            if case .finished = status { finished = true }
        }

        #expect(uvAttempts == 1)
        #expect(pinAttempts == 1)
        #expect(finished)
    }

    // MARK: - UV Without PIN Fallback

    @Test("uvInvalid on BIO-only (no clientPin) throws uvBlocked")
    func testUVInvalidOnBioOnlyThrowsBlocked() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 1 }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                Issue.record("PIN path reached without clientPin configured")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value()
        } catch {
            caught = error
        }

        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }

    @Test("uvBlocked on BIO-only (no clientPin) throws uvBlocked")
    func testUVBlockedOnBioOnlyThrows() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                Issue.record("PIN path reached without clientPin configured")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.uvBlocked, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value()
        } catch {
            caught = error
        }

        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - .pin Factory

    @Test(".pin(_) factory uses PIN directly without touching UV")
    func testPinFactorySkipsUV() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 5 }

        var uvAttempts = 0
        var pinAttempts = 0
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                uvAttempts += 1
                throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
            case .pin(let pin):
                pinAttempts += 1
                #expect(pin == "1234")
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        _ = try await client.getAssertion(Self.options, authorization: .pin("1234")).value()

        #expect(uvAttempts == 0, ".pin factory should skip UV; got \(uvAttempts) UV attempts")
        #expect(pinAttempts == 1)
    }

    // MARK: - uv: .required

    @Test("uv: .required throws uvBlocked on UV failure even when clientPin is configured")
    func testUVRequiredDoesNotFallBackToPIN() async throws {
        let mock = MockWebAuthnBackend()
        // PIN-and-UV authenticator. With useUV: .required we should NOT
        // fall through to PIN even though clientPin is set.
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 5 }

        var uvAttempts = 0
        let pinPromptCalls = Box(0)
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                uvAttempts += 1
                throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
            case .pin:
                Issue.record("PIN path reached despite uv: .required")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        let auth = WebAuthn.Authorization(
            providePIN: {
                pinPromptCalls.value += 1
                return .pin("never-asked")
            },
            uv: .required
        )

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: auth).value()
        } catch {
            caught = error
        }

        #expect(uvAttempts == 1)
        #expect(pinPromptCalls.value == 0, "PIN closure must not be invoked under uv: .required")
        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }

    @Test(".uvOnly factory throws uvBlocked instead of cancelled on UV failure with clientPin set")
    func testUVOnlyFactoryThrowsUVBlocked() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 5 }

        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                Issue.record("PIN path reached despite .uvOnly")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value()
        } catch {
            caught = error
        }

        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }
}
