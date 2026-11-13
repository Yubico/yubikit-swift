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

@Suite("CTAP operation serialization tests", .timeLimit(.minutes(1)))
struct CTAPOperationSerializationTests {

    @Test("a cancelled exchange drains before retry and ignores its stale cancel closure")
    func cancelledExchangeDrainsBeforeRetry() async throws {
        let connection = SerializedFIDOConnection(testing: ())
        let interface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)
        let oldCancel = Promise<@Sendable () async -> Void>()

        let firstStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let firstConsumer = Task {
            for try await status in firstStream {
                if case .waitingForUser(let cancel) = status {
                    await oldCancel.fulfill(cancel)
                    await cancel()
                }
            }
        }

        let staleCancel = try await oldCancel.value()
        try await connection.cancelSent.value()
        #expect(await connection.cancelCount == 1, "the first touch cancel must send CANCEL without another keepalive")

        let queuedStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let queuedConsumer = Task {
            for try await _ in queuedStream {}
        }

        // The queued operation must neither send nor keep waiting after its consumer cancels.
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.commands == [0x86, 0x90, 0x91])
        queuedConsumer.cancel()
        _ = await queuedConsumer.result
        #expect(await connection.commands == [0x86, 0x90, 0x91])

        let secondStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let secondConsumer = Task {
            for try await status in secondStream {
                if case .waitingForUser = status {
                    await staleCancel()
                    await connection.releaseRetryResponse.fulfill(())
                }
            }
        }

        // The retry must wait until the first command's final frame is read.
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.commands == [0x86, 0x90, 0x91])

        await connection.releaseCancelledResponse.fulfill(())
        try await connection.finalResponseReturned.value()
        // Receiving the final frame must not release a CANCEL send still in progress.
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.commands == [0x86, 0x90, 0x91])
        await connection.releaseCancelSend.fulfill(())
        _ = await firstConsumer.result
        _ = try await secondConsumer.value

        #expect(await connection.commands == [0x86, 0x90, 0x91, 0x90])
        #expect(await connection.cancelCount == 1)
        #expect(await !connection.overlappedCancelledExchange)
    }
}

// Holds a cancelled command's final frame to expose overlapping retries.
private actor SerializedFIDOConnection: FIDOConnection {
    nonisolated let mtu = 64

    let releaseCancelledResponse = Promise<Void>()
    let finalResponseReturned = Promise<Void>()
    let releaseCancelSend = Promise<Void>()
    let releaseRetryResponse = Promise<Void>()
    let cancelSent = Promise<Void>()

    private(set) var commands: [UInt8] = []
    private var channel = Data()
    private var initResponse: Data?
    private var operationCount = 0
    private var keepalivesRemaining = [1: 1, 2: 1]
    private var cancelledOperations: Set<Int> = []
    private var drainingCancelledResponse = false
    private var cancelSendInFlight = false
    private(set) var overlappedCancelledExchange = false

    var cancelCount: Int { commands.filter { $0 == 0x91 }.count }

    init(testing: Void) {}

    init() async throws(FIDOConnectionError) {
        fatalError("Use the test initializer")
    }

    static func makeConnection() async throws(FIDOConnectionError) -> SerializedFIDOConnection {
        fatalError("Use the test initializer")
    }

    func send(_ packet: Data) async throws(FIDOConnectionError) {
        channel = packet.prefix(4)
        commands.append(packet[4])
        switch packet[4] {
        case 0x86:  // INIT: nonce, channel 1, protocol 2, version 5.7.0, CBOR capability
            initResponse = frame(0x86, packet.subdata(in: 7..<15) + Data([0, 0, 0, 1, 2, 5, 7, 0, 0x04]))
        case 0x90:
            if drainingCancelledResponse || cancelSendInFlight { overlappedCancelledExchange = true }
            operationCount += 1
        case 0x91:
            await cancelSent.fulfill(())
            cancelledOperations.insert(operationCount)
            cancelSendInFlight = true
            do {
                try await releaseCancelSend.value()
            } catch {
                throw .transmitFailed("Cancel send gate failed", error)
            }
            cancelSendInFlight = false
        default:
            break
        }
    }

    func receive() async throws(FIDOConnectionError) -> Data {
        if let initResponse {
            self.initResponse = nil
            return initResponse
        }

        let currentOperation = operationCount
        if let remaining = keepalivesRemaining[currentOperation], remaining > 0 {
            keepalivesRemaining[currentOperation] = remaining - 1
            return frame(0xBB, Data([0x02]))
        }

        if currentOperation == 1 {
            // A silent authenticator stops sending keepalives until it receives CANCEL.
            for _ in 0..<50 {
                if cancelledOperations.contains(currentOperation) { break }
                try? await Task.sleep(for: .milliseconds(10))
            }
            guard cancelledOperations.contains(currentOperation) else {
                throw .receiveFailed("Expected CTAPHID_CANCEL", nil)
            }
            drainingCancelledResponse = true
            do {
                try await releaseCancelledResponse.value()
            } catch {
                throw .receiveFailed("Cancelled response gate failed", error)
            }
            drainingCancelledResponse = false
            await finalResponseReturned.fulfill(())
            return frame(0x90, Data([0x2D]))
        }

        do {
            try await releaseRetryResponse.value()
        } catch {
            throw .receiveFailed("Retry response gate failed", error)
        }
        return frame(0x90, Data([0x00]))
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }

    private func frame(_ command: UInt8, _ payload: Data) -> Data {
        var frame = channel + Data([command, 0, UInt8(payload.count)]) + payload
        frame.append(Data(count: mtu - frame.count))
        return frame
    }
}
