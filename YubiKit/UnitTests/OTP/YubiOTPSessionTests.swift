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

struct YubiOTPSessionTests {

    // MARK: - Opening a session

    @Test("opening over SmartCard selects the OTP application and parses the status struct")
    func opensOverSmartCard() async throws {
        let connection = MockSmartCardConnection(responses: [status([5, 7, 0], flags: 0x01)])

        let session = try await YubiOTP.Session.makeSession(connection: connection)

        #expect(await session.version == Version("5.7.0")!)
        #expect(try await session.configState.isConfigured(.one))
        #expect(try !(await session.configState).isConfigured(.two))
        #expect(await connection.sentRequests == [Data([0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 5, 0x27, 0x20, 1, 1])])
    }

    @Test("opening over the OTP transport parses the status struct from the first report")
    func opensOverOTP() async throws {
        let connection = try await FakeOTPConnection()
        connection.firmware = [5, 7, 0]

        let session = try await YubiOTP.Session.makeSession(connection: connection)

        #expect(await session.version == Version("5.7.0")!)
        #expect(try !(await session.configState).isConfigured(.one))
    }

    @Test("a truncated OTP status struct in the select response is rejected", arguments: [0, 5])
    func rejectsTruncatedSelect(length: Int) async throws {
        let connection = MockSmartCardConnection(responses: [Data(repeating: 5, count: length) + Data([0x90, 0])])
        do {
            _ = try await YubiOTP.Session.makeSession(connection: connection)
            Issue.record("Truncated OTP status was accepted")
        } catch .responseParseError {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("NFC reads the version from Management, then selects the OTP application")
    func nfcUsesManagementVersion() async throws {
        let connection = MockSmartCardConnection(responses: [Data("5.7.4".utf8) + Data([0x90, 0]), status([3, 0, 0])])

        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)

        #expect(await session.version == Version("5.7.4")!)
        #expect(
            await connection.sentRequests == [
                Data([0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 5, 0x27, 0x47, 0x11, 0x17]),
                Data([0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 5, 0x27, 0x20, 1, 1]),
            ]
        )
    }

    @Test("NFC on a YubiKey NEO uses the higher of the Management and OTP versions")
    func nfcNEOUsesHigherVersion() async throws {
        let connection = MockSmartCardConnection(responses: [managementSelect([3, 4, 0]), status([3, 4, 3])])

        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)

        #expect(await session.version == Version("3.4.3")!)
    }

    @Test("NFC falls back to the OTP status version when Management is not available")
    func nfcFallsBackWithoutManagement() async throws {
        let connection = MockSmartCardConnection(responses: [Data([0x6A, 0x82]), status([3, 4, 0])])

        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)

        #expect(await session.version == Version("3.4.0")!)
    }

    @Test("NFC propagates other Management selection failures")
    func nfcPropagatesManagementFailures() async throws {
        let connection = MockSmartCardConnection(responses: [Data([0x69, 0x82])])
        do {
            _ = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)
            Issue.record("A Management selection error was suppressed")
        } catch .failedResponse {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(await connection.sendCount == 1)
    }

    @Test("NFC rejects a malformed Management version")
    func nfcRejectsMalformedManagementVersion() async throws {
        let connection = MockSmartCardConnection(responses: [Data("invalid".utf8) + Data([0x90, 0])])
        do {
            _ = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)
            Issue.record("A malformed Management version was accepted")
        } catch .responseParseError {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test(
        "NFC on firmware 5.0.0 through 5.2.4 reports both slots as configured, also after a write",
        arguments: [[5, 0, 0], [5, 2, 4]] as [[UInt8]]
    )
    func legacyNFCUsesDummyState(version: [UInt8]) async throws {
        let connection = MockSmartCardConnection(responses: [
            managementSelect(version), status(version), Data([0x90, 0]),
        ])
        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)
        #expect(try await session.configState.isConfigured(.one))
        #expect(try await session.configState.isConfigured(.two))

        try await session.deleteConfiguration(in: .one)

        #expect(try await session.configState.isConfigured(.one))
        #expect(await connection.sendCount == 3)
    }

    @Test(
        "NFC outside firmware 5.0.0 through 5.2.4 reads the slot state",
        arguments: [[4, 4, 0], [5, 2, 5]] as [[UInt8]]
    )
    func nfcReadsSlotState(version: [UInt8]) async throws {
        let connection = MockSmartCardConnection(responses: [
            managementSelect(version), status(version), status(version, sequence: 1, flags: 0x01),
        ])
        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)
        #expect(try !(await session.configState).isConfigured(.one))

        try await session.putConfiguration(.hmacSHA1(key: Data([1])), in: .one)

        #expect(try await session.configState.isConfigured(.one))
        #expect(try !(await session.configState).isConfigured(.two))
    }

    @Test("the YubiKey NEO refreshes its status with a rejected scan map")
    func neoRefreshesStatus() async throws {
        let session = try await YubiOTP.Session.makeSession(connection: NEOConnection(failsAfterFirstReport: false))
        #expect(try await session.configState.isConfigured(.one))
        #expect(try await session.configState.isConfigured(.two))
    }

    @Test("the YubiKey NEO refresh propagates transport failures")
    func neoPropagatesTransportFailure() async throws {
        do {
            _ = try await YubiOTP.Session.makeSession(connection: NEOConnection(failsAfterFirstReport: true))
            Issue.record("The NEO refresh suppressed a disconnect")
        } catch .otpConnectionError(.connectionLost, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    // MARK: - Challenge-response

    @Test("a wired SmartCard session does not support challenge-response")
    func wiredSmartCardRejectsChallengeResponse() async throws {
        let connection = MockSmartCardConnection(responses: [status()])
        let session = try await YubiOTP.Session.makeSession(connection: connection)

        #expect(await session.supports(.challengeResponse) == false)
        do {
            _ = try await session.calculateHMACSHA1(challenge: Data([1]), in: .one).value
            Issue.record("A wired SmartCard session calculated a response")
        } catch .featureNotSupported {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(await connection.sendCount == 1)
    }

    @Test("an NFC session supports challenge-response")
    func nfcSupportsChallengeResponse() async throws {
        let response = Data(repeating: 0xAB, count: 20)
        let connection = MockSmartCardConnection(responses: [
            managementSelect([5, 7, 4]), status(), response + Data([0x90, 0]),
        ])
        let session = try await YubiOTP.Session.makeSession(connection: connection, isNFC: true)

        #expect(await session.supports(.challengeResponse))
        #expect(try await session.calculateHMACSHA1(challenge: Data([1]), in: .one).value == response)
    }

    // MARK: - Data responses

    @Test("an OTP data response with a bad CRC is rejected")
    func rejectsBadResponseCRC() async throws {
        let connection = try await FakeOTPConnection()
        connection.corruptsResponseCRC = true
        let session = try await YubiOTP.Session.makeSession(connection: connection)
        do {
            _ = try await session.getSerialNumber()
            Issue.record("A response with a bad CRC was accepted")
        } catch .responseParseError {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    // MARK: - Configuration state

    @Test("slot state queries reject firmware that does not report the state")
    func configStateRequiresFirmwareSupport() throws {
        #expect(throws: YubiOTP.SessionError.self) {
            try YubiOTP.ConfigState(version: Version("2.0.0")!, flags: 0x0F).isConfigured(.one)
        }
        #expect(try YubiOTP.ConfigState(version: Version("2.1.0")!, flags: 0x01).isConfigured(.one))
        #expect(throws: YubiOTP.SessionError.self) {
            try YubiOTP.ConfigState(version: Version("2.9.0")!, flags: 0x0F).isTouchTriggered(.one)
        }
        #expect(try YubiOTP.ConfigState(version: Version("3.0.0")!, flags: 0x04).isTouchTriggered(.one))
    }

    // MARK: - Writes

    @Test("a write rejects a status response without the high byte of the configuration state")
    func rejectsTruncatedWriteStatus() async throws {
        let connection = MockSmartCardConnection(responses: [status(), Data([5, 7, 4, 1, 1, 0x90, 0])])
        let session = try await YubiOTP.Session.makeSession(connection: connection)
        do {
            try await session.putConfiguration(.hmacSHA1(key: Data([1])), in: .one)
            Issue.record("A truncated write status was accepted")
        } catch .responseParseError {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test(
        "a SmartCard write must advance the programming sequence, except for the known resets",
        arguments: [
            ([5, 7, 4], 0x01, 3, true),  // advanced
            ([5, 7, 4], 0x01, 2, false),  // not advanced
            ([5, 7, 4], 0x00, 0, true),  // reset: no slot is configured
            ([5, 7, 4], 0x02, 0, false),  // reset while a slot is configured
            ([5, 4, 2], 0x02, 0, true),  // firmware that does not advance the sequence
        ] as [([UInt8], UInt8, UInt8, Bool)]
    )
    func writeRequiresAdvancedSequence(version: [UInt8], flags: UInt8, sequence: UInt8, isAccepted: Bool) async throws {
        let connection = MockSmartCardConnection(responses: [
            status(version, sequence: 2, flags: 0x03), status(version, sequence: sequence, flags: flags),
        ])
        let session = try await YubiOTP.Session.makeSession(connection: connection)
        do {
            try await session.deleteConfiguration(in: .one)
            #expect(isAccepted)
        } catch .commandRejected {
            #expect(!isAccepted)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("a SmartCard write that returns no status reads the status")
    func writeWithoutStatusReadsStatus() async throws {
        let connection = MockSmartCardConnection(responses: [
            status(), Data([0x90, 0]), status(sequence: 1, flags: 0x01),
        ])
        let session = try await YubiOTP.Session.makeSession(connection: connection)

        try await session.putConfiguration(.hmacSHA1(key: Data([1])), in: .one)

        #expect(try await session.configState.isConfigured(.one))
        #expect(try #require(await connection.sentRequests.last)[1] == 0x03)
    }

    @Test("an update checks firmware support before it sends a command")
    func updateChecksSupportBeforeSending() async throws {
        let connection = MockSmartCardConnection(responses: [status([2, 3, 0])])
        let session = try await YubiOTP.Session.makeSession(connection: connection)
        do {
            try await session.updateConfiguration(.init(options: .init(invertLED: true)), in: .one)
            Issue.record("An unsupported LED option was accepted")
        } catch .featureNotSupported {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(await connection.sendCount == 1)
    }

    // MARK: - Access codes

    @Test("each access code change writes the new code and authorizes with the current code", arguments: [false, true])
    func accessCodeChanges(update: Bool) async throws {
        let current = try YubiOTP.AccessCode(Data([1, 2, 3, 4, 5, 6]))
        let replacement = try YubiOTP.AccessCode(Data([6, 5, 4, 3, 2, 1]))
        let cases: [(YubiOTP.AccessCodeChange, Data)] = [
            (.unchanged, current.data), (.set(replacement), replacement.data), (.remove, Data(count: 6)),
        ]
        for (change, expected) in cases {
            let connection = MockSmartCardConnection(responses: [status(), status(sequence: 1)])
            let session = try await YubiOTP.Session.makeSession(connection: connection)

            try await write(session, update: update, accessCode: change, currentAccessCode: current)

            let request = try #require(await connection.sentRequests.last)
            #expect(request[2] == (update ? 0x04 : 0x01))
            #expect(request[4] == 58, "the configuration and the current access code")
            #expect(request.subdata(in: 43..<49) == expected)
            #expect(request.suffix(6) == current.data)
        }
    }

    @Test("an unprotected slot writes all-zero access codes by default", arguments: [false, true])
    func defaultAccessCodeIsZero(update: Bool) async throws {
        let connection = MockSmartCardConnection(responses: [status(), status(sequence: 1)])
        let session = try await YubiOTP.Session.makeSession(connection: connection)

        try await write(session, update: update)

        let request = try #require(await connection.sentRequests.last)
        #expect(request.subdata(in: 43..<49) == Data(count: 6))
        #expect(request.suffix(6) == Data(count: 6))
    }

    @Test("an access code that is not six bytes is rejected", arguments: [0, 5, 7])
    func rejectsInvalidAccessCodeLength(length: Int) {
        #expect(throws: YubiOTP.SessionError.self) {
            try YubiOTP.AccessCode(Data(repeating: 1, count: length))
        }
    }

    @Test("an all-zero access code is rejected")
    func rejectsAllZeroAccessCode() {
        #expect(throws: YubiOTP.SessionError.self) {
            try YubiOTP.AccessCode(Data(count: 6))
        }
    }

    @Test("an access code keeps its bytes, also from a slice")
    func accessCodeKeepsBytes() throws {
        let bytes = Data([0, 1, 2, 3, 4, 5, 6])
        #expect(try YubiOTP.AccessCode(bytes.dropFirst()).data == Data([1, 2, 3, 4, 5, 6]))
    }

    @Test(
        "firmware 4.3.2 through 4.3.5 rejects an access code change through an update",
        arguments: [[4, 3, 1], [4, 3, 2], [4, 3, 5], [4, 3, 6]] as [[UInt8]]
    )
    func updateAccessCodeFirmwareRestriction(version: [UInt8]) async throws {
        let current = try YubiOTP.AccessCode(Data([1, 2, 3, 4, 5, 6]))
        let changes: [YubiOTP.AccessCodeChange] = [
            .unchanged, .set(current), .set(try YubiOTP.AccessCode(Data(repeating: 7, count: 6))), .remove,
        ]
        for (index, change) in changes.enumerated() {
            let connection = MockSmartCardConnection(responses: [
                status(version), status(version, sequence: 1),
            ])
            let session = try await YubiOTP.Session.makeSession(connection: connection)
            let isRestricted = (2...5).contains(version[2]) && index >= 2
            do {
                try await session.updateConfiguration(.init(), in: .one, accessCode: change, currentAccessCode: current)
                #expect(!isRestricted)
            } catch .featureNotSupported {
                #expect(isRestricted)
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }
    }

    @Test("firmware 4.3.2 through 4.3.5 accepts an update that keeps an unprotected slot unprotected")
    func restrictedFirmwareAcceptsUnprotectedUpdate() async throws {
        let current: YubiOTP.AccessCode? = nil
        for change in [.unchanged, .remove] as [YubiOTP.AccessCodeChange] {
            let connection = MockSmartCardConnection(responses: [
                status([4, 3, 2]), status([4, 3, 2], sequence: 1),
            ])
            let session = try await YubiOTP.Session.makeSession(connection: connection)

            try await session.updateConfiguration(.init(), in: .one, accessCode: change, currentAccessCode: current)

            let request = try #require(await connection.sentRequests.last)
            #expect(request.subdata(in: 43..<49) == Data(count: 6))
            #expect(request.suffix(6) == Data(count: 6))
        }
    }

    // MARK: - Helpers

    private func write(
        _ session: YubiOTP.Session,
        update: Bool,
        accessCode: YubiOTP.AccessCodeChange = .unchanged,
        currentAccessCode: YubiOTP.AccessCode? = nil
    ) async throws(YubiOTP.SessionError) {
        if update {
            try await session.updateConfiguration(
                .init(),
                in: .one,
                accessCode: accessCode,
                currentAccessCode: currentAccessCode
            )
        } else {
            try await session.putConfiguration(
                .hmacSHA1(key: Data([1])),
                in: .one,
                accessCode: accessCode,
                currentAccessCode: currentAccessCode
            )
        }
    }

    // An OTP status struct followed by SW 9000.
    private func status(_ version: [UInt8] = [5, 7, 4], sequence: UInt8 = 0, flags: UInt8 = 0) -> Data {
        Data(version + [sequence, flags, 0, 0x90, 0])
    }

    private func managementSelect(_ version: [UInt8]) -> Data {
        Data(version.map(String.init).joined(separator: ".").utf8) + Data([0x90, 0])
    }
}

// A YubiKey NEO that reports both slots as configured only after the scan map refresh.
private actor NEOConnection: OTPConnection {
    private let failsAfterFirstReport: Bool
    private var reads = 0
    private var refreshed = false

    init(failsAfterFirstReport: Bool) { self.failsAfterFirstReport = failsAfterFirstReport }
    init() async throws(OTPConnectionError) { throw .noDevicesFound }
    static func makeConnection() async throws(OTPConnectionError) -> NEOConnection { throw .noDevicesFound }

    func receive() async throws(OTPConnectionError) -> Data {
        reads += 1
        if failsAfterFirstReport && reads > 1 { throw .connectionLost }
        return Data([0, 3, 4, 0, 0, refreshed ? 3 : 0, 0, 0])
    }

    func send(_ report: Data) async throws(OTPConnectionError) {
        // The last report of a frame.
        if report.last == 0x89 { refreshed = true }
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}
