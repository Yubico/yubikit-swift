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

@Suite("WebAuthn PIN Failure Tests", .serialized)
struct PINRetryTests {

    private static let options = WebAuthn.Authentication.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rpId: "example.com",
        userVerification: .required
    )

    // MARK: - One-shot Semantics

    @Test("pinInvalid throws pinRejected with the remaining retry count")
    func testPinInvalidThrowsRejected() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 7, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }

        var pinSubmissions: [String] = []
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin(let pin) = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            pinSubmissions.append(pin)
            throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .pin("wrong")).value
        } catch {
            caught = error
        }

        #expect(pinSubmissions == ["wrong"])
        guard case .pinRejected(let remaining, _) = caught else {
            Issue.record("Expected pinRejected, got \(String(describing: caught))")
            return
        }
        #expect(remaining == 7)
    }

    @Test("pinInvalid with retries == 0 throws pinBlocked")
    func testPinExhaustedThrowsBlocked() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 0, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .pin("bad")).value
        } catch {
            caught = error
        }

        guard case .pinBlocked = caught else {
            Issue.record("Expected pinBlocked, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - Error Propagation

    @Test("pinInvalid followed by a getPinRetries transport failure surfaces the transport error")
    func testPinInvalidGetRetriesFailureBubblesTransport() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinRetries = { () throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response in
            throw CTAP2.SessionError.connectionError(.connectionLost, source: .here())
        }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: .pin("wrong")).value
        } catch {
            caught = error
        }

        // The post-pinInvalid getPinRetries call failed — we must NOT synthesize
        // a pinBlocked (which would tell the user the PIN is locked when in fact
        // the connection just dropped).
        guard case .authenticatorNotAvailable = caught else {
            Issue.record("Expected authenticatorNotAvailable, got \(String(describing: caught))")
            return
        }
    }

    @Test("forcePinChange surfaces before the PIN closure is invoked")
    func testForcePinChangeThrowsBeforePrompt() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = {
            .stub(clientPin: true, pinUvAuthToken: true, forcePinChange: true)
        }
        mock.onGetUVRetries = { 0 }

        var pinUVTokenCalls = 0
        let pinPromptCalls = Box(0)
        mock.onGetPinUVToken = { _, _, _ throws(CTAP2.SessionError) in
            pinUVTokenCalls += 1
            throw CTAP2.SessionError.ctapError(.pinAuthInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        let auth = WebAuthn.Authorization(providePIN: {
            pinPromptCalls.value += 1
            return .pin("should-not-reach")
        })

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: auth).value
        } catch {
            caught = error
        }

        #expect(pinPromptCalls.value == 0)
        #expect(pinUVTokenCalls == 0)
        guard case .forcePinChange = caught else {
            Issue.record("Expected forcePinChange, got \(String(describing: caught))")
            return
        }
    }

    @Test("Falling to PIN path without clientPin configured throws pinNotSet")
    func testPinPathWithoutClientPinThrowsPinNotSet() async throws {
        let mock = MockWebAuthnBackend()
        // BIO-only authenticator: UV configured but clientPin is not.
        mock.onGetInfo = { .stub(clientPin: false, userVerification: true, pinUvAuthToken: true) }
        // Entering the ceremony with UV already blocked forces PIN fall-through.
        mock.onGetUVRetries = { 0 }

        var pinUVTokenCalls = 0
        let pinPromptCalls = Box(0)
        mock.onGetPinUVToken = { _, _, _ throws(CTAP2.SessionError) in
            pinUVTokenCalls += 1
            throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)

        let auth = WebAuthn.Authorization(providePIN: {
            pinPromptCalls.value += 1
            return .pin("should-not-reach")
        })

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            _ = try await client.getAssertion(Self.options, authorization: auth).value
        } catch {
            caught = error
        }

        // The SDK should recognise PIN is unavailable before invoking the
        // PIN closure or hitting the authenticator with a doomed call.
        #expect(pinPromptCalls.value == 0)
        #expect(pinUVTokenCalls == 0)
        guard case .pinNotSet = caught else {
            Issue.record("Expected pinNotSet, got \(String(describing: caught))")
            return
        }
    }
}
