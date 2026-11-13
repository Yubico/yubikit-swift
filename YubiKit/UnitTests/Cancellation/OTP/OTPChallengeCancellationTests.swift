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

@Suite("OTP challenge cancellation", .timeLimit(.minutes(1)))
struct OTPChallengeCancellationTests {

    private func session(_ connection: FakeOTPConnection) async throws -> YubiOTP.Session {
        try await YubiOTP.Session.makeSession(connection: connection)
    }

    @Test("cancelling while waiting for touch throws and resets the key")
    func cancelDuringTouch() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 200
        let session = try await session(connection)

        var caught: YubiOTP.SessionError?
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
        #expect(
            connection.writtenReports.contains { $0[7] == 0xFF },
            "cancelling should send the reset sentinel"
        )
    }

    @Test("cancelling the consuming task during touch resets the key and frees the session")
    func cancellingConsumerDuringTouch() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 200
        let session = try await session(connection)

        let consumer = Task {
            for try await status in await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two) {
                if case .waitingForUser = status { withUnsafeCurrentTask { $0?.cancel() } }
            }
        }
        _ = await consumer.result

        // Without cancellation, the abandoned challenge holds the session for 20 seconds.
        let serial = try await withDeadline { try await session.getSerialNumber() }
        #expect(serial == UInt(connection.serial))
        #expect(connection.writtenReports.contains { $0[7] == 0xFF }, "cancelling should send the reset sentinel")
    }

    @Test("another command waits until a touch command is cancelled")
    func serializesCommandsAcrossTouchWaits() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 200
        let session = try await session(connection)
        var serialTask: Task<UInt, any Error>?

        do {
            for try await status in await session.calculateHMACSHA1(
                challenge: Data("Hi There".utf8),
                in: .two
            ) {
                guard case .waitingForUser(let cancel) = status else { continue }
                serialTask = Task { try await session.getSerialNumber() }
                try await Task.sleep(for: .milliseconds(30))
                #expect(
                    connection.dispatchedCommands == [FakeOTPConnection.slotChallengeHMAC2],
                    "the serial command must not enter the transport while HMAC is in flight"
                )
                await cancel()
            }
            Issue.record("expected the challenge to be cancelled")
        } catch YubiOTP.SessionError.cancelled {
        }

        let task = try #require(serialTask)
        #expect(try await task.value == UInt(connection.serial))
        #expect(
            connection.dispatchedCommands
                == [FakeOTPConnection.slotChallengeHMAC2, FakeOTPConnection.slotDeviceSerial]
        )
    }

    @Test("a cancel closure from a completed challenge cannot cancel the next one")
    func oldCancelDoesNotAffectNextChallenge() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 1
        let session = try await session(connection)
        var oldCancel: (@Sendable () async -> Void)?

        for try await status in await session.calculateHMACSHA1(challenge: Data([1]), in: .one) {
            if case .waitingForUser(let cancel) = status { oldCancel = cancel }
        }

        let cancel = try #require(oldCancel)
        connection.touchReportsBeforeResponse = 2
        var response: Data?
        for try await status in await session.calculateHMACSHA1(challenge: Data([2]), in: .two) {
            if case .waitingForUser = status { await cancel() }
            if case .finished(let data) = status { response = data }
        }
        #expect(response == connection.hmacResponse)
    }

    @Test("cancelling a queued configuration write leaves the slot untouched")
    func cancellingQueuedWrite() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 20
        let session = try await session(connection)
        let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: Data(count: 16))
        var writeTask: Task<Void, any Error>?

        do {
            for try await status in await session.calculateHMACSHA1(challenge: Data([1]), in: .two) {
                guard case .waitingForUser(let cancel) = status else { continue }
                writeTask = Task { try await session.putConfiguration(configuration, in: .one) }
                try await Task.sleep(for: .milliseconds(30))
                let task = try #require(writeTask)
                task.cancel()
                do {
                    try await task.value
                    Issue.record("expected the queued write to be cancelled")
                } catch YubiOTP.SessionError.cancelled {
                }
                #expect(connection.dispatchedCommands == [FakeOTPConnection.slotChallengeHMAC2])
                await cancel()
            }
        } catch YubiOTP.SessionError.cancelled {
        }

        #expect(connection.dispatchedCommands == [FakeOTPConnection.slotChallengeHMAC2])
    }

    @Test("value reports caller cancellation")
    func valueReportsCancellation() async {
        let stream = YubiOTP.StatusStream<Data> { continuation in
            continuation.yield(.processing)
        }

        do {
            _ = try await withDeadline {
                withUnsafeCurrentTask { $0?.cancel() }
                return try await stream.value
            }
            Issue.record("Expected cancellation")
        } catch YubiOTP.SessionError.cancelled {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    // Returns nil if cancellation or response draining does not complete promptly.
    private func withDeadline<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T? {
        try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                return nil
            }
            defer { group.cancelAll() }
            return try await group.next() ?? nil
        }
    }
}
