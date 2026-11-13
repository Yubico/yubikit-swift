// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

import Foundation
import Testing

@_spi(YubiInternal) @testable import YubiKit

@Suite("WebAuthn CTAP stream completion errors", .timeLimit(.minutes(1)))
struct WebAuthnCancellationErrorTests {

    @Test(
        "empty CTAP streams preserve cancellation and missing-response errors",
        arguments: [false, true],
        [false, true]
    )
    func emptyCTAPStreamsMapErrors(cancelProducer: Bool, registration: Bool) async throws {
        let backend = MockCTAP2Backend()
        backend.onGetInfo = {
            CBOR.Value.map([
                .int(0x01): .array([.textString("FIDO_2_1")]),
                .int(0x03): .byteString(Data(repeating: 0, count: 16)),
                .int(0x04): .map([
                    .textString("up"): .boolean(true),
                    .textString("makeCredUvNotRqd"): .boolean(true),
                ]),
                .int(0x0A): .array([.int(-7)]),
            ]).cborDecoded()!
        }
        backend.onMakeCredential = { _ in
            if cancelProducer { withUnsafeCurrentTask { $0?.cancel() } }
            return CTAP2.StatusStream { $0.finish() }
        }
        backend.onGetAssertion = { _ in
            if cancelProducer { withUnsafeCurrentTask { $0?.cancel() } }
            return CTAP2.StatusStream { $0.finish() }
        }

        let client = try WebAuthn.Client.make(backend: backend)
        if registration {
            let options = WebAuthn.Registration.Options(
                challenge: Data(repeating: 1, count: 32),
                rp: .init(id: "example.com", name: "Example RP"),
                user: .init(id: Data([1]), name: "user", displayName: "User"),
                residentKey: .discouraged,
                userVerification: .discouraged
            )
            let stream = await client.makeCredential(options, authorization: .pin("1234"))
            await expectCancellationError(in: stream, expectedCancellation: cancelProducer)
        } else {
            let options = WebAuthn.Authentication.Options(
                challenge: Data(repeating: 2, count: 32),
                rpId: "example.com",
                allowCredentials: [],
                userVerification: .discouraged
            )
            let stream = await client.getAssertion(options, authorization: .pin("1234"))
            await expectCancellationError(in: stream, expectedCancellation: cancelProducer)
        }
    }

    private func expectCancellationError<Response: Sendable>(
        in stream: WebAuthn.StatusStream<Response>,
        expectedCancellation: Bool
    ) async {
        do {
            _ = try await stream.value
            Issue.record("An empty CTAP stream must fail")
        } catch {
            if expectedCancellation {
                guard case WebAuthn.ClientError.cancelled = error else {
                    Issue.record("Expected cancellation, got \(error)")
                    return
                }
            } else {
                guard case WebAuthn.ClientError.ctapError(.responseParseError, _) = error else {
                    Issue.record("Expected missing-response error, got \(error)")
                    return
                }
            }
        }
    }
}
