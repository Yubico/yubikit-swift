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

@Suite("CTAP2 StatusStream Tests", .timeLimit(.minutes(1)))
struct CTAPStatusStreamTests {

    @Test("value throws keepaliveCancel when the awaiting task is cancelled")
    func valueReportsCancellation() async throws {
        let stream = CTAP2.StatusStream<String> { continuation in
            continuation.yield(.processing)
        }
        let task = Task { try await stream.value }

        // Let the task suspend on the stream so the cancel interrupts the wait.
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch CTAP2.SessionError.ctapError(.keepaliveCancel, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("cancelling the consumer during a HID touch wait sends one CANCEL and reads the final response")
    func cancelDuringHIDTouch() async throws {
        let connection = KeepaliveFIDOConnection(keepalivesBeforeTimeout: 200)
        let interface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        await consumeUntilTouch(await interface.send(command: .selection))
        try await connection.finalResponseSent.value()

        #expect(await connection.commands == [0x86, 0x90, 0x91])
    }

    @Test("cancelling the consumer during a smart card touch wait polls with the cancel flag")
    func cancelDuringSmartCardTouch() async throws {
        let upNeeded = Data([0x02, 0x91, 0x00])
        let connection = MockSmartCardConnection(responses: [
            Data([0x90, 0x00]), upNeeded, upNeeded, Data([0x2D, 0x90, 0x00]),
        ])
        let interface = try await SmartCardInterface<CTAP2.SessionError>(connection: connection, application: .fido2)

        let start = ContinuousClock.now
        await consumeUntilTouch(await interface.send(command: .selection))
        while await connection.sendCount < 4 {
            try await Task.sleep(for: .milliseconds(10))
        }

        let polls = await connection.sentRequests.suffix(2)
        #expect(polls.map { $0[2] } == [0x11, 0x11], "both polls should carry P1_CANCEL_KEEP_ALIVE")
        #expect(ContinuousClock.now - start >= .milliseconds(200), "a cancelled poll loop must keep its interval")
    }

    // Iterates the stream and cancels the iterating task when the key waits for touch.
    private func consumeUntilTouch(_ stream: CTAP2.StatusStream<Void>) async {
        _ = await Task {
            for try await status in stream {
                if case .waitingForUser = status { withUnsafeCurrentTask { $0?.cancel() } }
            }
        }.result
    }
}

// Answers CTAPHID_INIT, then UPNEEDED keepalives until CTAPHID_CANCEL, then a final CBOR response.
private actor KeepaliveFIDOConnection: FIDOConnection {
    nonisolated let mtu = 64
    let finalResponseSent = Promise<Void>()
    private(set) var commands: [UInt8] = []
    private var channel = Data()
    private var initResponse: Data?
    private var keepalivesBeforeTimeout: Int
    private var keepalivesAfterCancel = 2
    private var cancelled = false

    init(keepalivesBeforeTimeout: Int) {
        self.keepalivesBeforeTimeout = keepalivesBeforeTimeout
    }

    init() async throws(FIDOConnectionError) { fatalError("Use the test initializer") }
    static func makeConnection() async throws(FIDOConnectionError) -> KeepaliveFIDOConnection {
        fatalError("Use the test initializer")
    }

    func send(_ packet: Data) async throws(FIDOConnectionError) {
        channel = packet.prefix(4)
        commands.append(packet[4])
        switch packet[4] {
        case 0x86:  // INIT: nonce, channel 1, protocol 2, version 5.7.0, CBOR capability
            initResponse = frame(0x86, packet.subdata(in: 7..<15) + Data([0, 0, 0, 1, 2, 5, 7, 0, 0x04]))
        case 0x91:
            cancelled = true
        default:
            break
        }
    }

    func receive() async throws(FIDOConnectionError) -> Data {
        if let response = initResponse {
            initResponse = nil
            return response
        }
        if cancelled ? keepalivesAfterCancel > 0 : keepalivesBeforeTimeout > 0 {
            if cancelled { keepalivesAfterCancel -= 1 } else { keepalivesBeforeTimeout -= 1 }
            await sleepIgnoringCancellation(for: .milliseconds(10))
            return frame(0xBB, Data([0x02]))
        }
        await finalResponseSent.fulfill(())
        return frame(0x90, Data([cancelled ? 0x2D : 0x00]))
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }

    private func frame(_ command: UInt8, _ payload: Data) -> Data {
        var frame = channel + Data([command, 0, UInt8(payload.count)]) + payload
        frame.append(Data(count: mtu - frame.count))
        return frame
    }
}
