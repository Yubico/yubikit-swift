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

struct PIVSessionTests {
    @Test("legacy retry queries preserve known counts and do not send PIN data")
    func legacyPinAttempts() async throws {
        let mock = MockSmartCardConnection(responses: [
            Data([0x90, 0x00]), Data([4, 3, 5, 0x90, 0x00]),
            Data([0x63, 0xc5]),  // Empty VERIFY reports five remaining attempts.
            Data([0x90, 0x00]),  // Correct PIN verification.
            Data([0x90, 0x00]),  // Empty VERIFY while already verified.
            Data([0x63, 0xc4]),  // Failed PIN change.
            Data([0x90, 0x00]),  // Empty VERIFY returns the cached count.
            Data([0x63, 0xc1]),  // Failed PUK change must not overwrite PIN retries.
            Data([0x90, 0x00]),
            Data([0x69, 0x83]),  // Blocked PIN.
        ])
        let session = try await PIVSession.makeSession(connection: mock)
        #expect(try await session.getPinAttempts() == 5)
        #expect(try await session.verifyPin("123456") == .success)
        #expect(try await session.getPinAttempts() == 5)
        await #expect { try await session.changePin(from: "000000", to: "284631") } throws: {
            guard case PIVSessionError.invalidPin(4, _) = $0 else { return false }
            return true
        }
        #expect(try await session.getPinAttempts() == 4)
        await #expect { try await session.changePuk(from: "00000000", to: "28463175") } throws: {
            guard case PIVSessionError.invalidPin(1, _) = $0 else { return false }
            return true
        }
        #expect(try await session.getPinAttempts() == 4)
        #expect(try await session.getPinAttempts() == 0)
        let requests = await mock.sentRequests
        for index in [2, 4, 6, 8, 9] {
            #expect(requests[index] == Data([0x00, 0x20, 0x00, 0x80]))
        }
    }

    @Test("management-key validation precedes sending and legacy firmware still accepts TDES")
    func managementKeyValidation() async throws {
        let mock = MockSmartCardConnection(responses: [
            Data([0x90, 0x00]), Data([4, 3, 5, 0x90, 0x00]), Data([0x90, 0x00]),
        ])
        let session = try await PIVSession.makeSession(connection: mock)
        for type in [PIV.ManagementKeyType.tripleDES, .aes128, .aes192, .aes256] {
            for length in [type.keyLength - 1, type.keyLength + 1] {
                await #expect {
                    try await session.setManagementKey(Data(count: length), type: type, requiresTouch: false)
                } throws: {
                    guard case PIVSessionError.invalidKeyLength = $0 else { return false }
                    return true
                }
            }
        }
        await #expect {
            try await session.setManagementKey(Data(count: 16), type: .aes128, requiresTouch: false)
        } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        #expect(await mock.sendCount == 2)
        try await session.setManagementKey(Data(count: 24), type: .tripleDES, requiresTouch: false)
        #expect(await mock.sendCount == 3)
    }
}
