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

    // MARK: - uvInvalid Surfaces with Retries

    @Test("uvInvalid throws uvRejected with retries remaining; PIN path not touched")
    func testUVInvalidThrowsRejected() async throws {
        let mock = MockWebAuthnBackend()
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
                Issue.record("PIN path reached on uvInvalid; should bubble as uvRejected")
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
            uv: .preferred
        )

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: auth).value
        } catch {
            caught = error
        }

        #expect(uvAttempts == 1)
        #expect(pinPromptCalls.value == 0, "PIN closure must not be invoked on uvInvalid")
        guard case .uvRejected(let remaining, _) = caught else {
            Issue.record("Expected uvRejected, got \(String(describing: caught))")
            return
        }
        #expect(remaining == 5)
    }

    @Test("uvInvalid on internal-UV path also surfaces as uvRejected")
    func testUVInvalidInternalUVPathThrowsRejected() async throws {
        let mock = MockWebAuthnBackend()
        // Internal-UV authenticator: UV configured but no pinUvAuthToken.
        // acquireAuthToken returns (token: nil, uv: true); the uvInvalid then
        // comes from the makeCredential/getAssertion command itself, not from
        // getPinUVToken — must still surface as uvRejected per the contract.
        mock.onGetInfo = { .stub(clientPin: false, userVerification: true, pinUvAuthToken: false) }
        mock.onGetUVRetries = { 4 }
        mock.onGetPinUVToken = { _, _, _ throws(CTAP2.SessionError) in
            Issue.record("getPinUVToken should not be called on internal-UV path")
            throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(error: .ctapError(.uvInvalid, source: .here())) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value
        } catch {
            caught = error
        }

        guard case .uvRejected(let remaining, _) = caught else {
            Issue.record("Expected uvRejected, got \(String(describing: caught))")
            return
        }
        #expect(remaining == 4)
    }

    @Test("uvInvalid followed by a getUVRetries transport failure surfaces the transport error")
    func testUVInvalidGetRetriesFailureBubblesTransport() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        // First call (initial probe) succeeds; second call (post-uvInvalid)
        // fails with a transport error. Must not be silently coerced to
        // uvBlocked — that would hide the real connection failure.
        let uvRetriesCalls = Box(0)
        mock.onGetUVRetries = { () throws(CTAP2.SessionError) -> Int in
            uvRetriesCalls.value += 1
            if uvRetriesCalls.value == 1 { return 5 }
            throw CTAP2.SessionError.connectionError(.connectionLost, source: .here())
        }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                Issue.record("PIN path reached on uvInvalid")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(
                Self.options,
                authorization: .init(providePIN: { .pin("ignored") }, uv: .preferred)
            ).value
        } catch {
            caught = error
        }

        guard case .authenticatorNotAvailable = caught else {
            Issue.record("Expected authenticatorNotAvailable, got \(String(describing: caught))")
            return
        }
    }

    @Test("uvInvalid with no UV retries left throws uvBlocked")
    func testUVInvalidExhaustedThrowsBlocked() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        // Initial probe sees retries left, but the post-uvInvalid re-fetch
        // returns 0 — same effect as uvBlocked.
        let uvRetriesCalls = Box(0)
        mock.onGetUVRetries = {
            uvRetriesCalls.value += 1
            return uvRetriesCalls.value == 1 ? 1 : 0
        }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                Issue.record("PIN path reached on exhausted uvInvalid")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(
                Self.options,
                authorization: .init(providePIN: { .pin("nope") }, uv: .preferred)
            ).value
        } catch {
            caught = error
        }

        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - One-shot UV with PIN Fallback

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

    @Test("uvInvalid on BIO-only (no clientPin) throws uvRejected with retries remaining")
    func testUVInvalidOnBioOnlyThrowsRejected() async throws {
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
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value
        } catch {
            caught = error
        }

        guard case .uvRejected(let remaining, _) = caught else {
            Issue.record("Expected uvRejected, got \(String(describing: caught))")
            return
        }
        #expect(remaining == 1)
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
            _ = try await client.getAssertion(Self.options, authorization: .uvOnly).value
        } catch {
            caught = error
        }

        guard case .uvBlocked = caught else {
            Issue.record("Expected uvBlocked, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - uv: .required

    @Test("uv: .required throws uvRejected on UV failure; PIN never touched")
    func testUVRequiredDoesNotFallBackToPIN() async throws {
        let mock = MockWebAuthnBackend()
        // PIN-and-UV authenticator. With uv: .required we should NOT
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
            _ = try await client.getAssertion(Self.options, authorization: auth).value
        } catch {
            caught = error
        }

        #expect(uvAttempts == 1)
        #expect(pinPromptCalls.value == 0, "PIN closure must not be invoked under uv: .required")
        guard case .uvRejected(let remaining, _) = caught else {
            Issue.record("Expected uvRejected, got \(String(describing: caught))")
            return
        }
        #expect(remaining == 5)
    }
}
