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

@Suite("SCP Full Stack Tests", .serialized)
struct SCPFullStackTests {

    @Test("Get supported CA identifiers")
    func getSupportedCaIdentifiers() async throws {
        try await runSCPTest {
            let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
            let info = try await securityDomainSession.getSupportedCAIdentifiers(kloc: true, klcc: true)
            #expect(info != [:], "Should return non-empty CA identifiers")
        }
    }

    @Test("Get key information")
    func getInformation() async throws {
        try await runSCPTest {
            let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
            let info = try await securityDomainSession.getKeyInformation()
            #expect(info != [:], "Should return non-empty key information")
        }
    }

    @Test("Test SCP11b authentication")
    func scp11b() async throws {
        try await runSCPTest {
            let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)
            let certificates = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
            guard let last = certificates.last,
                case let .ec(publicKey) = last.publicKey
            else {
                Issue.record("Failed to get EC public key from certificate")
                return
            }
            let scp11KeyParams = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
            let managementSession = try await ManagementSession.makeSession(
                connection: connection,
                scpKeyParams: scp11KeyParams
            )
            let deviceInfo = try await managementSession.getDeviceInfo()
            #expect(deviceInfo != nil, "Should successfully get device info with SCP11b")
        }
    }

    @Test("Test SCP03 authentication")
    func scp03() async throws {
        try await runSCPTest {
            let scpKeyParams = try SCP03KeyParams(
                keyRef: SCPKeyRef(kid: .scp03, kvn: 0xff),
                staticKeys: StaticKeys.defaultKeys()
            )
            let managementSession = try await ManagementSession.makeSession(
                connection: connection,
                scpKeyParams: scpKeyParams
            )
            let deviceInfo = try? await managementSession.getDeviceInfo()
            #expect(deviceInfo != nil, "Should successfully get device info with SCP03")
        }
    }
}
