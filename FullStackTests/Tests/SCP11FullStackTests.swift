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

class SCP11FullStackTests: XCTestCase {

    // Change Connection to test different types of connections
    typealias Connection = SmartCardConnection
    
    func testHandshake() throws {
        runAsyncTest() {
            do {
                let connection = try await AllowedConnections.anyConnection()
                let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
                let scpKeyRef = SCPKeyRef(kid: 0x13, kvn: 0x01)
                let certificates = try await securityDomainSession.getCertificateBundle(scpKeyRef: scpKeyRef)
                guard let last = certificates.last, let publicKey = SecCertificateCopyKey(last) else { fatalError() }
                let scp11KeyParams = SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
                let managementSession = try await ManagementSession.session(withConnection: connection, scpKeyParams: scp11KeyParams)
                let deviceInfo = try await managementSession.getDeviceInfo()
                XCTAssertNotNil(deviceInfo)
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
}
