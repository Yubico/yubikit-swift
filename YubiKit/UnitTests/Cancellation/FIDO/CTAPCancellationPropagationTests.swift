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

@Suite("CTAP cancellation propagation tests", .timeLimit(.minutes(1)))
struct CTAPCancellationPropagationTests {

    @Test("GetAssertions reports task cancellation as keepaliveCancel")
    func getAssertionsReportsCancellation() async throws {
        let connection = CancellationFIDOConnection(mode: .assertion)
        let interface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)
        let session = await CTAP2.Session(interface: .init(interface: interface))
        let parameters = CTAP2.GetAssertion.Parameters(
            rpId: "example.com",
            clientDataHash: Data(repeating: 0, count: 32)
        )
        let task = Task {
            try await session.nextAssertionForCancellationTest(parameters: parameters)
        }

        try await connection.assertionWaiting.value()
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch CTAP2.SessionError.ctapError(.keepaliveCancel, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        try await connection.cancelledResponseDrained.value()
        #expect(await connection.hidCancelCount == 1)
    }

    @Test("a failed automatic CANCEL send still drains before the next command")
    func failedAutomaticCancelDrainsBeforeRetry() async throws {
        let connection = CancellationFIDOConnection(
            mode: .assertion,
            failCancelSend: true,
            holdCancelledResponse: true,
            holdFirstKeepalive: true
        )
        let interface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)
        let parameters = CTAP2.GetAssertion.Parameters(
            rpId: "example.com",
            clientDataHash: Data(repeating: 0, count: 32)
        )
        let firstStream: CTAP2.StatusStream<CTAP2.GetAssertion.Response> = await interface.send(
            command: .getAssertion,
            payload: parameters
        )
        let firstConsumer = Task {
            for try await _ in firstStream {}
        }

        try await connection.firstKeepaliveWaiting.value()
        firstConsumer.cancel()
        await connection.releaseFirstKeepalive.fulfill(())
        try await connection.cancelSendFailed.value()
        let retryStream: CTAP2.StatusStream<Void> = await interface.send(command: .selection)
        let retryConsumer = Task {
            for try await _ in retryStream {}
        }

        await connection.releaseCancelledResponse.fulfill(())
        try await connection.retryCommandSent.value()
        _ = await firstConsumer.result
        _ = await retryConsumer.result

        #expect(await connection.hidCancelCount == 1)
        #expect(await !connection.overlappedCancelledOperation)
    }

    @Test("fingerprint enrollment retries wait for cancelled enrollment cleanup")
    func cancelledEnrollmentIsCleanedUp() async throws {
        let connection = CancellationFIDOConnection(
            mode: .bioEnrollment,
            holdEnrollmentCleanupResponse: true
        )
        let bioEnrollment = try await Self.bioEnrollment(using: connection)

        let consumer = Task {
            for try await _ in bioEnrollment.enroll() {}
        }

        try await connection.captureWaiting.value()

        let queuedRetryStarted = Promise<Void>()
        let queuedRetry = Task {
            await queuedRetryStarted.fulfill(())
            for try await _ in bioEnrollment.enroll() {}
        }
        try await queuedRetryStarted.value()
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.enrollmentSubcommands == [0x01, 0x02])
        queuedRetry.cancel()
        _ = await queuedRetry.result

        let retryStarted = Promise<Void>()
        let retry = Task {
            await retryStarted.fulfill(())
            for try await _ in bioEnrollment.enroll() {}
        }
        try await retryStarted.value()
        try await Task.sleep(for: .milliseconds(50))
        #expect(await connection.enrollmentSubcommands == [0x01, 0x02])

        consumer.cancel()
        _ = await consumer.result
        try await connection.cancelEnrollmentSent.value()
        #expect(await connection.enrollmentSubcommands == [0x01, 0x02, 0x03])

        await connection.releaseEnrollmentCleanupResponse.fulfill(())
        try await connection.enrollmentCleanupResponseReturned.value()
        try await connection.retryEnrollmentBeginSent.value()
        _ = await retry.result

        #expect(await connection.enrollmentSubcommands == [0x01, 0x02, 0x03, 0x01])
        #expect(await connection.hidCancelCount == 1)
    }

    @Test("an enrollment sequence created by a cancelled task sends no commands")
    func preCancelledEnrollmentDoesNotStart() async throws {
        let connection = CancellationFIDOConnection(mode: .bioEnrollment)
        let bioEnrollment = try await Self.bioEnrollment(using: connection)
        let stream = await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return bioEnrollment.enroll()
        }.value

        var iterator = stream.makeAsyncIterator()
        #expect(try await iterator.next() == nil)
        #expect(await connection.enrollmentSubcommands.isEmpty)
        #expect(await connection.hidCancelCount == 0)
    }

    private static func bioEnrollment(
        using connection: CancellationFIDOConnection
    ) async throws -> CTAP2.BioEnrollment {
        let interface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)
        let session = await CTAP2.Session(interface: .init(interface: interface))
        let token = try CTAP2.Token(data: Data(repeating: 0, count: 16), protocolVersion: .v1)
        return try await session.bioEnrollment(token: token)
    }
}

extension CTAP2.Session {
    fileprivate func nextAssertionForCancellationTest(
        parameters: CTAP2.GetAssertion.Parameters
    ) async throws(CTAP2.SessionError) -> CTAP2.GetAssertion.Response? {
        let sequence = await getAssertions(parameters: parameters)
        let iterator = sequence.makeAsyncIterator()
        return try await iterator.next()
    }
}

private actor CancellationFIDOConnection: FIDOConnection {
    enum Mode: Sendable, Equatable {
        case assertion
        case bioEnrollment
    }

    private enum ActiveOperation {
        case assertion
        case bioCapture
    }

    nonisolated let mtu = 64

    let assertionWaiting = Promise<Void>()
    let firstKeepaliveWaiting = Promise<Void>()
    let releaseFirstKeepalive = Promise<Void>()
    let captureWaiting = Promise<Void>()
    let cancelledResponseDrained = Promise<Void>()
    let releaseCancelledResponse = Promise<Void>()
    let cancelSendFailed = Promise<Void>()
    let retryCommandSent = Promise<Void>()
    let cancelEnrollmentSent = Promise<Void>()
    let releaseEnrollmentCleanupResponse = Promise<Void>()
    let enrollmentCleanupResponseReturned = Promise<Void>()
    let retryEnrollmentBeginSent = Promise<Void>()

    private let mode: Mode
    private let holdEnrollmentCleanupResponse: Bool
    private let failCancelSend: Bool
    private let holdCancelledResponse: Bool
    private let holdFirstKeepalive: Bool
    private var channel = Data()
    private var initResponse: Data?
    private var responses: [Data] = []
    private var activeOperation: ActiveOperation?
    private var cleanupResponsePending = false
    private var hidCancelled = false
    private var cancelFailed = false
    private var cancelledResponsePending = false
    private var firstKeepaliveHeld = false
    private var enrollmentBeginCount = 0
    private(set) var hidCancelCount = 0
    private(set) var overlappedCancelledOperation = false
    private(set) var enrollmentSubcommands: [UInt64] = []

    init(
        mode: Mode,
        holdEnrollmentCleanupResponse: Bool = false,
        failCancelSend: Bool = false,
        holdCancelledResponse: Bool = false,
        holdFirstKeepalive: Bool = false
    ) {
        self.mode = mode
        self.holdEnrollmentCleanupResponse = holdEnrollmentCleanupResponse
        self.failCancelSend = failCancelSend
        self.holdCancelledResponse = holdCancelledResponse
        self.holdFirstKeepalive = holdFirstKeepalive
    }

    init() async throws(FIDOConnectionError) {
        fatalError("Use the test initializer")
    }

    static func makeConnection() async throws(FIDOConnectionError) -> CancellationFIDOConnection {
        fatalError("Use the test initializer")
    }

    func send(_ packet: Data) async throws(FIDOConnectionError) {
        channel = packet.prefix(4)
        if cancelledResponsePending && packet[4] != 0x91 {
            overlappedCancelledOperation = true
        }
        switch packet[4] {
        case 0x86:  // CTAPHID_INIT
            initResponse = frame(
                0x86,
                packet.subdata(in: 7..<15) + Data([0, 0, 0, 1, 2, 5, 7, 0, 0x04])
            )
        case 0x90:  // CTAPHID_CBOR
            try await handleCBORRequest(packet)
        case 0x91:  // CTAPHID_CANCEL
            hidCancelCount += 1
            if failCancelSend {
                cancelFailed = true
                cancelledResponsePending = true
                await cancelSendFailed.fulfill(())
                throw .transmitFailed("Scripted CANCEL failure", nil)
            }
            hidCancelled = true
            cancelledResponsePending = true
        default:
            throw .transmitFailed("Unexpected HID command", nil)
        }
    }

    func receive() async throws(FIDOConnectionError) -> Data {
        if let initResponse {
            self.initResponse = nil
            return initResponse
        }
        if !responses.isEmpty {
            return responses.removeFirst()
        }
        if cleanupResponsePending {
            do {
                try await releaseEnrollmentCleanupResponse.value()
            } catch {
                throw .receiveFailed("Enrollment cleanup response gate failed", error)
            }
            cleanupResponsePending = false
            await enrollmentCleanupResponseReturned.fulfill(())
            return frame(0x90, successResponse(nil))
        }
        if let activeOperation {
            if cancelFailed {
                if holdCancelledResponse {
                    do {
                        try await releaseCancelledResponse.value()
                    } catch {
                        throw .receiveFailed("Cancelled response gate failed", error)
                    }
                }
                self.activeOperation = nil
                cancelFailed = false
                cancelledResponsePending = false
                await cancelledResponseDrained.fulfill(())
                return frame(0x90, Data([0x2D]))
            }
            if hidCancelled {
                self.activeOperation = nil
                hidCancelled = false
                cancelledResponsePending = false
                await cancelledResponseDrained.fulfill(())
                return frame(0x90, Data([0x2D]))
            }
            switch activeOperation {
            case .assertion:
                await assertionWaiting.fulfill(())
                if holdFirstKeepalive && !firstKeepaliveHeld {
                    firstKeepaliveHeld = true
                    await firstKeepaliveWaiting.fulfill(())
                    do {
                        try await releaseFirstKeepalive.value()
                    } catch {
                        throw .receiveFailed("Keepalive gate failed", error)
                    }
                }
            case .bioCapture:
                await captureWaiting.fulfill(())
            }
            return frame(0xBB, Data([0x02]))
        }
        throw .receiveFailed("No scripted response is available", nil)
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }

    private func handleCBORRequest(_ packet: Data) async throws(FIDOConnectionError) {
        let length = Int(packet[5]) << 8 | Int(packet[6])
        let payload = packet.subdata(in: 7..<(7 + length))
        guard let command = payload.first else {
            throw .transmitFailed("Empty CTAP request", nil)
        }

        switch command {
        case 0x02 where mode == .assertion:
            activeOperation = .assertion
        case 0x0B:
            await retryCommandSent.fulfill(())
            responses.append(frame(0x90, successResponse(nil)))
        case 0x04 where mode == .bioEnrollment:
            let response = CBOR.Value.map([
                .int(0x01): .array([.textString("FIDO_2_1")]),
                .int(0x03): .byteString(Data(repeating: 0, count: 16)),
                .int(0x04): .map([.textString("bioEnroll"): .boolean(false)]),
            ])
            responses.append(frame(0x90, successResponse(response)))
        case 0x09 where mode == .bioEnrollment:
            let requestData = Data(payload.dropFirst())
            let request: CBOR.Value? = try? requestData.decode()
            let subcommand = request?.mapValue?[.int(0x02)]?.uint64Value
            switch subcommand {
            case .some(0x01):
                enrollmentSubcommands.append(0x01)
                enrollmentBeginCount += 1
                if enrollmentBeginCount > 1 {
                    await retryEnrollmentBeginSent.fulfill(())
                }
                let response = CBOR.Value.map([
                    .int(0x04): .byteString(Data([0xAA])),
                    .int(0x05): .int(0),
                    .int(0x06): .int(enrollmentBeginCount == 1 ? 1 : 0),
                ])
                responses.append(frame(0x90, successResponse(response)))
            case .some(0x02):
                enrollmentSubcommands.append(0x02)
                activeOperation = .bioCapture
            case .some(0x03):
                enrollmentSubcommands.append(0x03)
                if holdEnrollmentCleanupResponse {
                    cleanupResponsePending = true
                } else {
                    responses.append(frame(0x90, successResponse(nil)))
                }
                await cancelEnrollmentSent.fulfill(())
            default:
                // getModality does not include a bioEnrollment subcommand.
                let response = CBOR.Value.map([.int(0x01): .int(0x01)])
                responses.append(frame(0x90, successResponse(response)))
            }
        default:
            throw .transmitFailed("Unexpected CTAP command", nil)
        }
    }

    private func successResponse(_ value: CBOR.Value?) -> Data {
        var response = Data([0x00])
        if let value { response.append(value.encode()) }
        return response
    }

    private func frame(_ command: UInt8, _ payload: Data) -> Data {
        var frame = channel + Data([command, 0, UInt8(payload.count)]) + payload
        frame.append(Data(count: mtu - frame.count))
        return frame
    }
}
