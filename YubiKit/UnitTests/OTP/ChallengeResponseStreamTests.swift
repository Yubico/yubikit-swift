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

/// Covers the touch and cancellation path of ``YubiOTP/Session/calculateHMACSHA1(challenge:in:)``,
/// which mirrors `event`/`on_keepalive` in `yubikit.core.otp` and the Rust
/// `test_calculate_hmac_sha1_cancel`.
struct ChallengeResponseStreamTests {

    private func session(_ connection: FakeOTPConnection) async throws -> YubiOTP.Session {
        try await YubiOTP.Session.makeSession(connection: connection)
    }

    @Test("a slot that answers immediately yields only .finished")
    func immediateResponse() async throws {
        let connection = try await FakeOTPConnection()
        let session = try await session(connection)

        var statuses: [String] = []
        var response: Data?
        for try await status in await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two) {
            switch status {
            case .processing: statuses.append("processing")
            case .waitingForUser: statuses.append("waitingForUser")
            case .finished(let data): response = data
            }
        }

        #expect(statuses.isEmpty)
        #expect(response == connection.hmacResponse)
    }

    @Test("a touch-triggered slot yields .waitingForUser before finishing")
    func waitsForTouch() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 3
        let session = try await session(connection)

        var sawWaiting = false
        var response: Data?
        for try await status in await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two) {
            switch status {
            case .waitingForUser: sawWaiting = true
            case .finished(let data): response = data
            case .processing: break
            }
        }

        #expect(sawWaiting, "the stream should report the pending touch")
        #expect(response == connection.hmacResponse)
    }

    @Test("duplicate waiting statuses are collapsed into one")
    func deduplicatesWaiting() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 5
        let session = try await session(connection)

        var waitingCount = 0
        for try await status in await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two) {
            if case .waitingForUser = status { waitingCount += 1 }
        }
        #expect(waitingCount == 1, "five busy reports should collapse to a single status")
    }

    @Test("cancelling while waiting for touch throws and resets the key")
    func cancelDuringTouch() async throws {
        let connection = try await FakeOTPConnection()
        // Long enough that the cancel lands while the key is still reporting "waiting".
        connection.touchReportsBeforeResponse = 200
        let session = try await session(connection)

        var caught: YubiOTPSessionError?
        do {
            for try await status in await session.calculateHMACSHA1(
                challenge: Data("Hi There".utf8),
                in: .two
            ) {
                if case .waitingForUser(let cancel) = status {
                    await cancel()
                }
            }
        } catch {
            caught = error
        }

        guard case .cancelled = caught else {
            Issue.record("expected .cancelled, got \(String(describing: caught))")
            return
        }
        // The host must tell the key to drop its pending response, or the next command desynchronises.
        #expect(
            connection.writtenReports.contains { $0[7] == 0xFF },
            "cancelling should send the reset sentinel"
        )
    }

    @Test("value ignores intermediate statuses")
    func valueDrainsTheStream() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 2
        let session = try await session(connection)

        let response = try await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two).value
        #expect(response == connection.hmacResponse)
    }

    @Test("a challenge longer than 64 bytes is rejected through the stream")
    func rejectsOversizedChallenge() async throws {
        let connection = try await FakeOTPConnection()
        let session = try await session(connection)

        await #expect(throws: YubiOTPSessionError.self) {
            _ = try await session.calculateHMACSHA1(challenge: Data(repeating: 0, count: 65), in: .two).value
        }
    }
}
