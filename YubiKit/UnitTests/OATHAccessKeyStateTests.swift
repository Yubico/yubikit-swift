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

// TwinKit reports a modern OATH version and does not model the NEO lock after SETCODE.
@Suite("OATH access key state")
struct OATHAccessKeyStateTests {
    private let key = Data(repeating: 0x11, count: 16)

    @Test("legacy SETCODE reselects, validates, and permits listing")
    func legacySetCode() async throws {
        let card = ScriptedOATHCard(majorVersion: 2)
        let session = try await OATHSession.makeSession(connection: card)
        try await session.setAccessKey(key)

        #expect(await session.hasAccessKey)
        #expect(await session.isLocked == false)
        #expect(try await session.listCredentials().count == 1)
        #expect(await card.validateRequestCorrect)
        #expect(await card.instructions == [0xa4, 0x03, 0xa4, 0xa3, 0xa1])
    }

    @Test("legacy reselect failure retains locked state")
    func legacyReselectFailure() async throws {
        let card = ScriptedOATHCard(majorVersion: 2, failure: .reselect)
        let session = try await OATHSession.makeSession(connection: card)
        await #expect(throws: OATHSessionError.self) {
            try await session.setAccessKey(key)
        }
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)
        #expect(await card.instructions == [0xa4, 0x03, 0xa4])
    }

    @Test("legacy VALIDATE status failure retains locked state")
    func legacyValidateFailure() async throws {
        let card = ScriptedOATHCard(majorVersion: 2, failure: .validateStatus)
        let session = try await OATHSession.makeSession(connection: card)
        await #expect(throws: OATHSessionError.self) {
            try await session.setAccessKey(key)
        }
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)
        #expect(await card.instructions == [0xa4, 0x03, 0xa4, 0xa3])
    }

    @Test("legacy VALIDATE HMAC mismatch retains locked state")
    func legacyInvalidValidationHMAC() async throws {
        let card = ScriptedOATHCard(majorVersion: 2, failure: .invalidValidationHMAC)
        let session = try await OATHSession.makeSession(connection: card)
        await #expect(throws: OATHSessionError.self) {
            try await session.setAccessKey(key)
        }
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)
        #expect(await card.validateRequestCorrect)
        #expect(await card.instructions == [0xa4, 0x03, 0xa4, 0xa3])
    }

    @Test("modern SETCODE does not reselect")
    func modernSetCode() async throws {
        let card = ScriptedOATHCard(majorVersion: 5)
        let session = try await OATHSession.makeSession(connection: card)
        try await session.setAccessKey(key)
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked == false)
        #expect(await card.instructions == [0xa4, 0x03])
    }

    @Test("failed SETCODE preserves prior access key state")
    func setCodeFailure() async throws {
        let card = ScriptedOATHCard(majorVersion: 2, initialChallenge: true, failure: .setCode)
        let session = try await OATHSession.makeSession(connection: card)
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)
        await #expect(throws: OATHSessionError.self) {
            try await session.setAccessKey(key)
        }
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)
        #expect(await card.instructions == [0xa4, 0x03])
    }

    @Test("legacy SETCODE after VALIDATE does not reselect")
    func legacySetCodeAfterValidate() async throws {
        let card = ScriptedOATHCard(majorVersion: 2, initialChallenge: true)
        let session = try await OATHSession.makeSession(connection: card)
        try await session.unlock(accessKey: key)
        try await session.setAccessKey(key)
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked == false)
        #expect(try await session.listCredentials().count == 1)
        #expect(await card.instructions == [0xa4, 0xa3, 0x03, 0xa1])
    }

    @Test("reset reselects and refreshes salt, device ID, and access key state")
    func resetRefreshesState() async throws {
        let card = ScriptedOATHCard(majorVersion: 5, initialChallenge: true)
        let session = try await OATHSession.makeSession(connection: card)
        let deviceId = await session.deviceId
        let derivedKey = try await session.deriveAccessKey(from: "password")
        #expect(await session.hasAccessKey)
        #expect(await session.isLocked)

        try await session.reset()

        #expect(await session.hasAccessKey == false)
        #expect(await session.isLocked == false)
        #expect(await session.deviceId != deviceId)
        #expect(try await session.deriveAccessKey(from: "password") != derivedKey)
        #expect(try await session.listCredentials().count == 1)
        #expect(await card.instructions == [0xa4, 0x04, 0xa4, 0xa1])
    }
}

private actor ScriptedOATHCard: SmartCardConnection {
    enum Failure { case none, setCode, reselect, validateStatus, invalidValidationHMAC }

    private let majorVersion: UInt8
    private let initialChallenge: Bool
    private let failure: Failure
    private let key = Data(repeating: 0x11, count: 16)
    private let challenge = Data(repeating: 0x42, count: 8)
    private var selectCount = 0
    private var hasKey: Bool
    private var validated = false
    private var salt = Data(repeating: 0x33, count: 8)
    private var locked: Bool
    private(set) var instructions: [UInt8] = []
    private(set) var validateRequestCorrect = false

    init(majorVersion: UInt8, initialChallenge: Bool = false, failure: Failure = .none) {
        self.majorVersion = majorVersion
        self.initialChallenge = initialChallenge
        self.failure = failure
        self.hasKey = initialChallenge
        self.locked = initialChallenge
    }

    init() async throws(SmartCardConnectionError) { fatalError("Use scripted initializer") }
    static func makeConnection() async throws(SmartCardConnectionError) -> ScriptedOATHCard {
        fatalError("Use scripted initializer")
    }
    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        guard data.count >= 4 else { return Data([0x6d, 0x00]) }
        let instruction = data[1]
        instructions.append(instruction)
        switch instruction {
        case 0xa4:
            selectCount += 1
            if selectCount > 1 && failure == .reselect { return Data([0x6f, 0x00]) }
            validated = false
            var payload = TKBERTLVRecord(tag: 0x79, value: Data([majorVersion, 0, 0])).data
            payload.append(TKBERTLVRecord(tag: 0x71, value: salt).data)
            if hasKey {
                payload.append(TKBERTLVRecord(tag: 0x74, value: challenge).data)
            }
            return payload + Data([0x90, 0x00])
        case 0x03:
            if failure == .setCode { return Data([0x6f, 0x00]) }
            hasKey = true
            // Legacy applets lock after SETCODE unless the key was validated in this selection.
            locked = majorVersion < 3 && !validated
            return Data([0x90, 0x00])
        case 0x04:
            hasKey = false
            locked = false
            validated = false
            salt = Data(repeating: 0x44, count: 8)
            return Data([0x90, 0x00])
        case 0xa3:
            if failure == .validateStatus { return Data([0x6a, 0x80]) }
            guard data.count > 5,
                let values = TKBERTLVRecord.dictionaryOfData(from: data.dropFirst(5)),
                let response = values[0x75], let clientChallenge = values[0x74]
            else {
                return Data([0x6a, 0x80])
            }
            validateRequestCorrect = response == challenge.hmacSha1(key: key)
            guard validateRequestCorrect else { return Data([0x6a, 0x80]) }
            let mac =
                failure == .invalidValidationHMAC
                ? Data(repeating: 0, count: 20) : clientChallenge.hmacSha1(key: key)
            if failure != .invalidValidationHMAC {
                locked = false
                validated = true
            }
            return TKBERTLVRecord(tag: 0x75, value: mac).data + Data([0x90, 0x00])
        case 0xa1:
            if locked { return Data([0x69, 0x82]) }
            let account = Data("test".utf8)
            return TKBERTLVRecord(tag: 0x72, value: Data([0x21]) + account).data + Data([0x90, 0x00])
        default:
            return Data([0x6d, 0x00])
        }
    }
}
