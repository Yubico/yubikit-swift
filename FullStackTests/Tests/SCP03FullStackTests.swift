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

import XCTest
@testable import YubiKit
import CryptoTokenKit

class SCP03FullStackTests: XCTestCase {
    
    static let defaultKeyRef = SCPKeyRef(kid: 0x01, kvn: 0xff)
    static let defaultKey = Data([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
    static let defaultKeyParams = SCP03KeyParams(keyRef: defaultKeyRef, staticKeys: StaticKeys(enc: defaultKey, mac: defaultKey, dek: defaultKey))

    func testDefaultKeysConnectionSCP03() throws {
        runAsyncTest() {
            do {
                let connection = try await AllowedConnections.anyConnection()
                let managementSession = try  await ManagementSession.session(withConnection: connection, scpKeyParams: Self.defaultKeyParams)
                let deviceInfo = try await managementSession.getDeviceInfo()
                XCTAssertNotNil(deviceInfo)
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    func testImportKey() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()
            let resetSession = try await SecurityDomainSession.session(withConnection: connection)
            try await resetSession.reset()
            print("✅ Session reset")
            let session = try await SecurityDomainSession.session(withConnection: connection, scpKeyParams: Self.defaultKeyParams)
            let sk = Data(hexEncodedString: "40 41 42 43 44 45 46 47 40 41 42 43 44 45 46 47")!
            let staticKeys = StaticKeys(enc: sk, mac: sk, dek: sk)
            let keyRef = SCPKeyRef(kid: 0x01, kvn: 0x01)
            let params = SCP03KeyParams(keyRef: keyRef, staticKeys: staticKeys)
            print("✅ about to import key")
            try await session.putKey(keyRef: keyRef, keys: staticKeys, replaceKvn: 0)
            print("✅ key imported")
            let newSession = try await SecurityDomainSession.session(withConnection: connection, scpKeyParams: params)
        }

    }
}
