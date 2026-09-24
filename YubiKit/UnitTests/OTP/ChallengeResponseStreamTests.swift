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

    @Test(
        "a short challenge is padded to 64 bytes with a byte that differs from its last byte",
        arguments: [(Data(), 0x00), (Data([1, 2]), 0x00), (Data([1, 0]), 0x01)] as [(Data, UInt8)]
    )
    func padsChallenge(challenge: Data, padByte: UInt8) async throws {
        let connection = try await FakeOTPConnection()
        let session = try await session(connection)

        _ = try await session.calculateHMACSHA1(challenge: challenge, in: .one).value

        #expect(connection.dispatchedPayloads.last == challenge + Data(repeating: padByte, count: 64 - challenge.count))
    }

    @Test("a touch-triggered slot yields one .waitingForUser before finishing")
    func waitsForTouch() async throws {
        let connection = try await FakeOTPConnection()
        connection.touchReportsBeforeResponse = 5
        let session = try await session(connection)

        var waitingCount = 0
        var response: Data?
        for try await status in await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two) {
            switch status {
            case .waitingForUser: waitingCount += 1
            case .finished(let data): response = data
            case .processing: break
            }
        }

        #expect(waitingCount == 1, "five busy reports should collapse to a single status")
        #expect(response == connection.hmacResponse)
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

        await #expect(throws: YubiOTP.SessionError.self) {
            _ = try await session.calculateHMACSHA1(challenge: Data(repeating: 0, count: 65), in: .two).value
        }
    }

    // MARK: - value

    @Test("value rejects a stream that ends without a response")
    func valueRejectsMissingResponse() async {
        let stream = YubiOTP.StatusStream<Data> { continuation in
            continuation.yield(.processing)
            continuation.finish()
        }

        do {
            _ = try await withDeadline { try await stream.value }
            Issue.record("Expected an error")
        } catch YubiOTP.SessionError.dataProcessingError {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
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

    // Returns nil if the operation does not finish in time, so a stalled stream fails the test.
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
