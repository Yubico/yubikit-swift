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

@Suite("Smart card CTAP serialization", .timeLimit(.minutes(1)))
struct SmartCardCTAPSerializationTests {
    @Test("a retry waits for the cancelled poll response and ignores a stale cancel closure")
    func cancelledPollDrainsBeforeRetry() async throws {
        let connection = DrainingCTAPSmartCardConnection(testing: ())
        let interface = try await SmartCardInterface<CTAP2.SessionError>(connection: connection, application: .fido2)
        let oldCancel = Promise<@Sendable () async -> Void>()
        let firstStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let firstConsumer = Task {
            for try await status in firstStream {
                if case let .waitingForUser(cancel) = status {
                    await oldCancel.fulfill(cancel)
                    withUnsafeCurrentTask { $0?.cancel() }
                }
            }
        }
        let staleCancel = try await oldCancel.value()
        try await connection.cancelPollStarted.value()
        _ = await firstConsumer.result

        let queuedStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let queuedStarted = Promise<Void>()
        let queuedConsumer = Task {
            await queuedStarted.fulfill(())
            try await queuedStream.value
        }
        try await queuedStarted.value()
        queuedConsumer.cancel()
        do {
            try await queuedConsumer.value
            Issue.record("Expected queued cancellation")
        } catch CTAP2.SessionError.ctapError(.keepaliveCancel, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        let retry: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let retryConsumer = Task {
            for try await status in retry {
                if case .waitingForUser = status { await staleCancel() }
            }
        }
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.commandCount == 1)
        await connection.releaseCancelledPoll.fulfill(())
        try await retryConsumer.value

        #expect(await connection.commandCount == 2)
        #expect(await connection.pollFlags == [0x11, 0x00])
        #expect(await !connection.overlappedCancelledPoll)
    }
}

private actor DrainingCTAPSmartCardConnection: SmartCardConnection {
    let cancelPollStarted = Promise<Void>()
    let releaseCancelledPoll = Promise<Void>()
    private(set) var commandCount = 0
    private(set) var pollFlags: [UInt8] = []
    private(set) var overlappedCancelledPoll = false
    private var drainingCancelledPoll = false

    init(testing: Void) {}
    init() async throws(SmartCardConnectionError) { fatalError("Use the test initializer") }
    static func makeConnection() async throws(SmartCardConnectionError) -> DrainingCTAPSmartCardConnection {
        fatalError("Use the test initializer")
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        switch data[1] {
        case 0xa4:
            return Data([0x90, 0x00])
        case 0x10:
            if drainingCancelledPoll { overlappedCancelledPoll = true }
            commandCount += 1
            return Data([0x02, 0x91, 0x00])
        case 0x11:
            pollFlags.append(data[2])
            if commandCount == 1 {
                drainingCancelledPoll = true
                await cancelPollStarted.fulfill(())
                do {
                    try await releaseCancelledPoll.value()
                } catch {
                    throw .connectionLost
                }
                drainingCancelledPoll = false
                return Data([0x2d, 0x90, 0x00])
            }
            return Data([0x00, 0x90, 0x00])
        default:
            throw .connectionLost
        }
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}
