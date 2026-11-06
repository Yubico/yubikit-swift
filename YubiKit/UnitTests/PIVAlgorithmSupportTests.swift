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

struct PIVAlgorithmSupportTests {
    // Android 3.3.0 PivSessionTest: firmware boundary and unsupported-operation cases.
    @Test(arguments: [("5.7.2", true), ("6.0.0", false)])
    func algorithmSupport(firmware: String, supported: Bool) async throws {
        let version = Version(firmware)!
        let mock = MockSmartCardConnection(responses: [
            Data([0x90, 0]), Data([version.major, version.minor, version.micro, 0x90, 0]), Data([0x90, 0]),
        ])
        let session = try await PIVSession.makeSession(connection: mock)
        #expect(await session.supports(.rsa1024) == supported)
        #expect(await session.supports(.tripleDESManagementKey) == supported)
        guard !supported else { return }

        let key = try RSA.PrivateKey.random(keySize: .bits1024)
        await #expect { try await session.generateKey(in: .signature, type: .rsa(.bits1024)) } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        await #expect {
            try await session.putPrivateKey(key, in: .signature, pinPolicy: .defaultPolicy, touchPolicy: .defaultPolicy)
        } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        await #expect {
            try await session.setManagementKey(Data(count: 24), type: .tripleDES, requiresTouch: false)
        } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        #expect(await mock.sendCount == 2)
        try await session.setManagementKey(Data(count: 24), type: .aes192, requiresTouch: false)
        #expect(await mock.sendCount == 3)
    }
}
