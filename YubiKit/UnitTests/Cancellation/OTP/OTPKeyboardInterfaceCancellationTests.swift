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

@Suite("OTP keyboard cancellation")
struct OTPKeyboardInterfaceCancellationTests {

    @Test("a started configuration write completes after caller cancellation")
    func startedWriteCompletes() async throws {
        let connection = try await FakeOTPConnection()
        connection.busyReportsAfterChunk = 1
        let interface = try await OTPKeyboardInterface<YubiOTP.SessionError>(connection: connection)
        connection.onReportSent = { withUnsafeCurrentTask { $0?.cancel() } }

        let status = try await Task {
            try await interface.sendAndReceive(
                slot: FakeOTPConnection.slotConfig1,
                data: Data(repeating: 0xAB, count: 64)
            )
        }.value

        #expect(status[3] == 1)
        #expect(connection.writtenChunkSequences == Array(0...9))
        #expect(!connection.writtenReports.contains { $0[7] == 0xFF })
    }

    @Test("a pre-cancelled caller sends no OTP command")
    func preCancelledCommandDoesNotStart() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface<ManagementSessionError>(connection: connection)

        await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try await interface.sendAndReceive(slot: 0x13)
                Issue.record("A cancelled command was sent")
            } catch ManagementSessionError.cancelled {
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }.value

        #expect(connection.writtenReports.isEmpty)
    }

    @Test("cancellation during status and readiness reads sends no OTP frame", arguments: [2, 3])
    func cancellationBeforeFirstReportDoesNotStartFrame(cancelOnRead: Int) async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface<YubiOTP.SessionError>(connection: connection)
        connection.onReportReceived = { count in
            if count == cancelOnRead { withUnsafeCurrentTask { $0?.cancel() } }
        }

        await Task {
            do {
                _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotConfig1)
                Issue.record("A cancelled frame was sent")
            } catch YubiOTP.SessionError.cancelled {
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }.value

        #expect(connection.writtenReports.isEmpty)
    }
}
