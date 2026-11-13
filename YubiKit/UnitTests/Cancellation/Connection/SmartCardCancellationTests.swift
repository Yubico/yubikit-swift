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

import CryptoTokenKit
import Foundation
import Testing

@testable import YubiKit

@Suite("SmartCard cancellation admission")
struct SmartCardCancellationTests {

    @Test("A cancelled session admission is rejected before selecting an applet")
    func cancelledSessionIsNotSelected() async throws {
        let connection = MockSmartCardConnection(responses: [])

        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            _ = try await SmartCardInterface<OATHSessionError>(connection: connection, application: .oath)
        }

        do {
            _ = try await operation.value
            Issue.record("A cancelled session was selected")
        } catch OATHSessionError.connectionError(.cancelled, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(await connection.sendCount == 0)
    }

    @Test("A cancelled applet command is rejected before sending")
    func cancelledCommandIsNotSent() async throws {
        let connection = MockSmartCardConnection(responses: [selectSuccess])
        let interface = try await SmartCardInterface<OATHSessionError>(connection: connection, application: .oath)
        let apdu = APDU(cla: 0, ins: 0x01, p1: 0, p2: 0)

        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            let _: Data = try await interface.send(apdu: apdu)
        }

        do {
            try await operation.value
            Issue.record("A cancelled command was sent")
        } catch OATHSessionError.connectionError(.cancelled, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(await connection.sendCount == 1)
    }

    @Test("A cancelled Management read does not fetch the next page")
    func cancelledManagementPageReadStops() async throws {
        let select = Data("5.8.0".utf8) + Data([0x90, 0])
        let firstPage = Data([6, 0x04, 1, 3, 0x10, 1, 1]) + Data([0x90, 0])
        let configRequest = Data([0, 0x1d, 0, 0])
        let connection = CancellingSmartCardConnection(
            responses: [select, firstPage],
            cancelAfterRequest: configRequest
        )
        let session = try await Management.Session.makeSession(connection: connection)
        let read = Task { try await session.getDeviceInfo() }

        do {
            _ = try await read.value
            Issue.record("A cancelled Management read fetched all pages")
        } catch ManagementSessionError.connectionError(.cancelled, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(await connection.sendCount == 2)
    }

    @Test("A cancelled command still drains its APDU response continuation")
    func cancelledCommandDrainsContinuation() async throws {
        let apdu = APDU(cla: 0, ins: 0x01, p1: 0, p2: 0)
        let firstChunk = Data([0xaa, 0xbb])
        let finalChunk = Data([0xcc, 0xdd])
        let connection = CancellingSmartCardConnection(
            responses: [
                selectSuccess,
                firstChunk + Data([0x61, UInt8(finalChunk.count)]),
                finalChunk + Data([0x90, 0]),
            ],
            cancelAfterRequest: apdu.data
        )
        let interface = try await SmartCardInterface<OATHSessionError>(connection: connection, application: .oath)

        let command = Task {
            let result: Data = try await interface.send(apdu: apdu)
            return result
        }
        let result = try await command.value

        #expect(result == firstChunk + finalChunk)
        #expect(await connection.sendCount == 3)
    }

    @Test("A SmartCard OTP write reads status after its admitted mutation")
    func cancelledOTPWriteStillReadsAcknowledgement() async throws {
        let connection = CancellingSmartCardConnection(
            responses: [
                otpStatus(sequence: 0, flags: 0),
                Data([0x90, 0]),
                otpStatus(sequence: 1, flags: 1),
            ],
            cancelAfterInstruction: 0x01
        )
        let session = try await YubiOTP.Session.makeSession(connection: connection)
        let write = Task {
            try await session.putConfiguration(.hmacSHA1(key: Data([1])), in: .one)
        }

        try await write.value

        #expect(await connection.sendCount == 3)
        #expect(await connection.lastRequest?.dropFirst().first == 0x03)
    }

    @Test("Cancellation from an optional SCP read is propagated")
    func cancelledOptionalSCPReadIsNotSwallowed() async throws {
        let keyIdentifierData =
            TKBERTLVRecord(tag: 0x80, value: Data([1, 2, 3])).data
            + TKBERTLVRecord(tag: 0x81, value: Data([0x11, 1])).data
        let klocRequest = APDU(cla: 0, ins: 0xca, p1: 0xff, p2: 0x33)
        let connection = CancellingSmartCardConnection(
            responses: [selectSuccess, keyIdentifierData + Data([0x90, 0])],
            cancelAfterRequest: klocRequest.data
        )
        let session = try await SecurityDomainSession.makeSession(connection: connection)
        let read = Task { try await session.getSupportedCAIdentifiers(kloc: true, klcc: true) }

        do {
            _ = try await read.value
            Issue.record("Cancellation of the second SCP read was swallowed")
        } catch SCPError.connectionError(.cancelled, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(await connection.sendCount == 2)
    }

    private let selectSuccess = Data([0x01, 0x02, 0x90, 0x00])

    private func otpStatus(sequence: UInt8, flags: UInt8) -> Data {
        Data([5, 7, 4, sequence, flags, 0, 0, 0x90, 0])
    }
}

private actor CancellingSmartCardConnection: SmartCardConnection {

    private let responses: [Data]
    private let cancelAfterRequest: Data?
    private let cancelAfterInstruction: UInt8?
    private var nextResponse = 0
    private(set) var sendCount = 0
    private(set) var lastRequest: Data?

    init(
        responses: [Data],
        cancelAfterRequest: Data? = nil,
        cancelAfterInstruction: UInt8? = nil
    ) {
        self.responses = responses
        self.cancelAfterRequest = cancelAfterRequest
        self.cancelAfterInstruction = cancelAfterInstruction
    }

    init() async throws(SmartCardConnectionError) {
        fatalError("Use the test initializer")
    }

    static func makeConnection() async throws(SmartCardConnectionError) -> CancellingSmartCardConnection {
        fatalError("Use the test initializer")
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        sendCount += 1
        lastRequest = data
        precondition(nextResponse < responses.count, "CancellingSmartCardConnection ran out of responses")
        let response = responses[nextResponse]
        nextResponse += 1
        if (cancelAfterRequest.map { data == $0 } ?? false)
            || (cancelAfterInstruction.map { data.count > 1 && data[1] == $0 } ?? false)
        {
            withUnsafeCurrentTask { $0?.cancel() }
        }
        return response
    }

    func close(error: Error?) async {}

    func waitUntilClosed() async -> Error? { nil }
}
