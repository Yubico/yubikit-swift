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
    @Test(arguments: [
        ("5.7.2", false, true), ("5.7.2", true, false),
        ("6.0.0", false, false), ("6.0.0", true, false),
    ])
    func featureSupport(firmware: String, isFIPSKey: Bool, supported: Bool) {
        let version = Version(firmware)!
        for feature in [PIVSessionFeature.rsa1024, .tripleDESManagementKey] {
            #expect(feature.isSupported(by: version, isFIPSKey: isFIPSKey) == supported)
            let firmwareFeature: any SessionFeature = feature
            #expect(firmwareFeature.isSupported(by: version) == (version < Version("6.0.0")!))
        }
        #expect(PIVSessionFeature.aesKey.isSupported(by: version, isFIPSKey: isFIPSKey))
    }

    @Test("Older FIPS keys still accept TDES management keys", arguments: ["4.4.0", "5.4.3"])
    func legacyFIPSManagementKey(firmware: String) async throws {
        let (session, _) = try await makePIVSession(
            firmware: firmware,
            responses: [
                Data([0x90, 0])  // Set the TDES management key.
            ],
            isFIPSKey: true
        )
        #expect(await session.supports(.tripleDESManagementKey))
        try await session.setManagementKey(Data(count: 24), type: .tripleDES, requiresTouch: false)
    }

    @Test(arguments: [
        ("5.7.2", Bool?.none, true), ("5.7.2", false, true), ("5.7.2", true, false),
        ("6.0.0", nil, false), ("6.0.0", false, false), ("6.0.0", true, false),
    ])
    func algorithmSupport(firmware: String, isFIPSKey: Bool?, supported: Bool) async throws {
        let (session, mock) = try await makePIVSession(
            firmware: firmware,
            responses: [
                Data([0x90, 0])  // Set the management key.
            ],
            isFIPSKey: isFIPSKey
        )
        #expect(await session.supports(.rsa1024) == supported)
        #expect(await session.supports(.tripleDESManagementKey) == supported)
        if supported {
            try await session.setManagementKey(Data(count: 24), type: .tripleDES, requiresTouch: false)
            return
        }

        let sendsBeforeRejection = await mock.sendCount
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
        #expect(await mock.sendCount == sendsBeforeRejection)
        try await session.setManagementKey(Data(count: 24), type: .aes192, requiresTouch: false)
    }
}
