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

@Suite("WebAuthn UV → PIN Mid-Flight Downgrade", .serialized)
struct UVFallbackToPINTests {

    private static let options = WebAuthn.Authentication.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rpId: "example.com",
        userVerification: .required
    )

    // MARK: - fallbackToPIN exposed and routed into PIN path

    @Test("fallbackToPIN closure is non-nil when clientPin set and uv: .preferred")
    func testFallbackExposed() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        let gate = Promise<Void>()
        let pinAttempts = Box(0)

        mock.onGetPinUVTokenUpdates = { method, _, _ in
            switch method {
            case .uv:
                return uvWaitingStream(gate: gate)
            case .pin(let pin):
                #expect(pin == "1234")
                pinAttempts.value += 1
                return .mocked(
                    .finished(CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2))
                )
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)
        let auth = WebAuthn.Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)

        var sawUVWaiting = false
        var sawFinished = false
        for try await status in stream {
            switch status {
            case .waitingForUserVerification(_, let fallback):
                sawUVWaiting = true
                let fallback = try #require(fallback, "fallbackToPIN should be exposed")
                await fallback()
            case .finished:
                sawFinished = true
            default:
                break
            }
        }

        #expect(sawUVWaiting)
        #expect(sawFinished)
        #expect(pinAttempts.value == 1, "Ceremony should have continued via PIN path")
    }

    // MARK: - fallback suppressed under uv: .required

    @Test("fallbackToPIN is nil under uv: .required")
    func testFallbackSuppressedWhenUVRequired() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        let gate = Promise<Void>()
        mock.onGetPinUVTokenUpdates = {
            method,
            _,
            _ throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token> in
            guard case .uv = method else {
                Issue.record("PIN path reached under uv: .required")
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            return uvWaitingStream(gate: gate)
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)
        let auth = WebAuthn.Authorization(providePIN: { .pin("never-asked") }, uv: .required)
        let stream = await client.getAssertion(Self.options, authorization: auth)

        var fallbackVisibility: Bool?
        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            for try await status in stream {
                if case .waitingForUserVerification(let cancel, let fallback) = status {
                    fallbackVisibility = fallback != nil
                    // Aborting via cancel surfaces .cancelled.
                    await cancel()
                }
            }
        } catch {
            caught = error
        }

        #expect(fallbackVisibility == false, "fallbackToPIN must be nil under uv: .required")
        guard case .cancelled = caught else {
            Issue.record("Expected .cancelled, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - fallback suppressed without clientPin

    @Test("fallbackToPIN is nil when no clientPin is configured")
    func testFallbackSuppressedWithoutPIN() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }

        let gate = Promise<Void>()
        mock.onGetPinUVTokenUpdates = { _, _, _ in uvWaitingStream(gate: gate) }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)
        let auth = WebAuthn.Authorization(providePIN: { .pin("never-asked") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)

        var fallbackVisibility: Bool?
        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            for try await status in stream {
                if case .waitingForUserVerification(let cancel, let fallback) = status {
                    fallbackVisibility = fallback != nil
                    await cancel()
                }
            }
        } catch {
            caught = error
        }

        #expect(fallbackVisibility == false, "fallbackToPIN must be nil without clientPin")
        guard case .cancelled = caught else {
            Issue.record("Expected .cancelled, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - cancel without fallback throws .cancelled

    @Test("cancel without fallback aborts ceremony with .cancelled")
    func testCancelAbortsCeremony() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        let gate = Promise<Void>()
        let pinAttempts = Box(0)
        mock.onGetPinUVTokenUpdates = { method, _, _ in
            switch method {
            case .uv:
                return uvWaitingStream(gate: gate)
            case .pin:
                pinAttempts.value += 1
                return .mocked(
                    .finished(CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2))
                )
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)
        let auth = WebAuthn.Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            for try await status in stream {
                if case .waitingForUserVerification(let cancel, _) = status {
                    await cancel()
                }
            }
        } catch {
            caught = error
        }

        guard case .cancelled = caught else {
            Issue.record("Expected .cancelled, got \(String(describing: caught))")
            return
        }
        #expect(pinAttempts.value == 0, "PIN path must not run after a plain cancel")
    }
}

// MARK: - Test Helpers

/// Builds a `getPinUVTokenUpdates` body that yields `.waitingForUser` and
/// finalises with `keepaliveCancel` once the gate fulfils.
private func uvWaitingStream(gate: Promise<Void>) -> CTAP2.StatusStream<CTAP2.Token> {
    CTAP2.StatusStream<CTAP2.Token> { continuation in
        Task {
            continuation.yield(.waitingForUser(cancel: { await gate.fulfill(()) }))
            try? await gate.value()
            continuation.yield(error: .ctapError(.keepaliveCancel, source: .here()))
        }
    }
}
