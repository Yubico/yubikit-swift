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

final class SCP03FullStackTests: XCTestCase {

    func testDefaultKeys() throws {
        runSCPTest { [self] in

            let managementSession = try await ManagementSession.makeSession(
                connection: connection,
                scpKeyParams: defaultKeyParams
            )
            _ = try await managementSession.getDeviceInfo()
            XCTAssertTrue(true)  // reached here
        }
    }

    func testImportKey() throws {
        runSCPTest { [self] in

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.makeSession(connection: connection).reset()

            // new session that authenticates with the default keys
            let session = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: defaultKeyParams
            )

            // new keys
            let sk = Data([
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            ])
            let staticKeys = StaticKeys(enc: sk, mac: sk, dek: sk)
            let keyRef = SCPKeyRef(kid: .scp03, kvn: 0x01)
            let params = try SCP03KeyParams(keyRef: keyRef, staticKeys: staticKeys)

            // import new key
            try await session.putStaticKeys(staticKeys, for: keyRef, replacing: 0)

            // new session that authenticates with the default keys
            let newSession = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params)
            let _ = try await newSession.getKeyInformation()
            XCTAssertTrue(true)  // reached here

            // new session that authenticates with the default keys
            // shouldn't work anymore and must throw an error
            do {
                let _ = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: defaultKeyParams
                )
                XCTFail("Should not reach here")
            } catch {
                XCTAssertTrue(true)
            }
        }
    }

    func testDeleteKey() throws {
        runSCPTest { [self] in

            // generate two random static key sets
            let sk1enc = generateRandomKey()
            let sk1mac = generateRandomKey()
            let sk1dek = generateRandomKey()
            let staticKeys1 = StaticKeys(enc: sk1enc, mac: sk1mac, dek: sk1dek)

            let sk2enc = generateRandomKey()
            let sk2mac = generateRandomKey()
            let sk2dek = generateRandomKey()
            let staticKeys2 = StaticKeys(enc: sk2enc, mac: sk2mac, dek: sk2dek)

            let keyRef1 = SCPKeyRef(kid: .scp03, kvn: 0x10)
            let keyRef2 = SCPKeyRef(kid: .scp03, kvn: 0x55)
            let params1 = try SCP03KeyParams(keyRef: keyRef1, staticKeys: staticKeys1)
            let params2 = try SCP03KeyParams(keyRef: keyRef2, staticKeys: staticKeys2)

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.makeSession(connection: connection).reset()

            // import first key using default credentials
            var session = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: defaultKeyParams
            )
            try await session.putStaticKeys(staticKeys1, for: keyRef1, replacing: 0)

            // authenticate with first key and import second
            session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
            try await session.putStaticKeys(staticKeys2, for: keyRef2, replacing: 0)

            // verify authentication with both keys
            _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
            _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)

            // delete the first key
            session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
            try await session.deleteKey(for: keyRef1)

            // authentication with first key should fail
            do {
                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                XCTFail("Should not reach here")
            } catch {
                XCTAssertTrue(true)
            }

            // second key still works
            session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)

            // delete the second (last) key
            try await session.deleteKey(for: keyRef2, deleteLast: true)

            // authentication with second key should now fail
            do {
                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
                XCTFail("Should not reach here")
            } catch {
                XCTAssertTrue(true)
            }
        }
    }

    func testReplaceKey() throws {
        runSCPTest { [self] in

            let sk1 = StaticKeys(enc: generateRandomKey(), mac: generateRandomKey(), dek: generateRandomKey())
            let sk2 = StaticKeys(enc: generateRandomKey(), mac: generateRandomKey(), dek: generateRandomKey())

            let keyRef1 = SCPKeyRef(kid: .scp03, kvn: 0x10)
            let keyRef2 = SCPKeyRef(kid: .scp03, kvn: 0x55)

            let params1 = try SCP03KeyParams(keyRef: keyRef1, staticKeys: sk1)
            let params2 = try SCP03KeyParams(keyRef: keyRef2, staticKeys: sk2)

            // reset to factory default
            try await SecurityDomainSession.makeSession(connection: connection).reset()

            // import keyRef1 with default credentials
            var session = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: defaultKeyParams
            )
            try await session.putStaticKeys(sk1, for: keyRef1, replacing: 0)

            // authenticate with keyRef1 and replace it with keyRef2
            session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
            try await session.putStaticKeys(sk2, for: keyRef2, replacing: keyRef1.kvn)

            // keyRef1 should fail now
            do {
                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                XCTFail("Should not reach here")
            } catch {
                XCTAssertTrue(true)
            }

            // keyRef2 should work
            session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
            _ = try await session.getKeyInformation()
            XCTAssertTrue(true)
        }
    }

    func testWrongKey() throws {
        runSCPTest { [self] in

            let sk = StaticKeys(enc: generateRandomKey(), mac: generateRandomKey(), dek: generateRandomKey())
            let keyRef = SCPKeyRef(kid: .scp03, kvn: 0x01)
            let params = try SCP03KeyParams(keyRef: keyRef, staticKeys: sk)

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.makeSession(connection: connection).reset()

            // Try authenticating with a wrong key
            do {
                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params)
                XCTFail("Should not reach here")
            } catch {
                XCTAssertTrue(true)
            }

            // Check that secure APDU still fails even if session is created
            do {
                let session = try? await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params)
                if let session {
                    _ = try await session.getKeyInformation()
                    XCTFail("Should not be able to send secure command")
                }
            } catch {
                XCTAssertTrue(true)
            }

            // Authenticate successfully with default key after failure
            let session = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: defaultKeyParams
            )
            _ = try await session.getKeyInformation()
            XCTAssertTrue(true)
        }
    }
}

private func generateRandomKey() -> Data {
    Data((0..<16).map { _ in UInt8.random(in: 0x00...0xFF) })
}
