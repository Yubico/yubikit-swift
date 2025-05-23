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
import XCTest

@testable import YubiKit

class SCPFullStackTests: XCTestCase {

    func testGetSupportedCaIdentifiers() throws {
        runSCPTest { [self] in
            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
            let info = try await securityDomainSession.getSupportedCaIdentifiers(kloc: true, klcc: true)
            XCTAssertTrue(info != [:])
        }
    }

    func testGetInformation() throws {
        runSCPTest { [self] in
            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
            let info = try await securityDomainSession.getKeyInformation()
            XCTAssertTrue(info != [:])
        }
    }

    func testSCP11b() throws {
        runSCPTest { [self] in
            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)
            let certificates = try await securityDomainSession.getCertificateBundle(scpKeyRef: scpKeyRef)
            guard let last = certificates.last,
                let publicKey = last.publicKey?.asEC()
            else {
                XCTFail()
                return
            }
            let scp11KeyParams = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
            let managementSession = try await ManagementSession.session(
                withConnection: connection,
                scpKeyParams: scp11KeyParams
            )
            let deviceInfo = try await managementSession.getDeviceInfo()
            XCTAssertNotNil(deviceInfo)
        }
    }

    func testSCP03() throws {
        runSCPTest { [self] in
            let scpKeyParams = try SCP03KeyParams(
                keyRef: SCPKeyRef(kid: .scp03, kvn: 0xff),
                staticKeys: StaticKeys.defaultKeys()
            )
            let managementSession = try await ManagementSession.session(
                withConnection: connection,
                scpKeyParams: scpKeyParams
            )
            let deviceInfo = try? await managementSession.getDeviceInfo()
            XCTAssertNotNil(deviceInfo)
        }
    }
}
