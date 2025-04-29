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

class SCP11bFullStackTests: XCTestCase {

    static let defaultKeyParams: SCP03KeyParams = {
        let defaultKeyRef = SCPKeyRef(kid: .scp03, kvn: 0xff)
        let defaultKey = Data([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                               0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
        return SCP03KeyParams(keyRef: defaultKeyRef,
                              staticKeys: StaticKeys(enc: defaultKey, mac: defaultKey, dek: defaultKey))
    }()

    func testScp11bAuthenticate() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.session(withConnection: connection).reset()

            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

            let chain = try await securityDomainSession.getCertificateBundle(scpKeyRef: scpKeyRef)
            let leaf: SecCertificate = chain.last!
            var trust: SecTrust?
            SecTrustCreateWithCertificates(leaf, SecPolicyCreateBasicX509(), &trust)
            _ = SecTrustCopyKey(trust!)! // make sure we can read the public key

            do {
                try await securityDomainSession.verifyScp11bAuth()
            } catch {
                if case let SCPError.wrapped(error) = error, let error = error as? ResponseError {
                    // we cannot use the default key to authenticate
                    XCTAssert(error.responseStatus.status == .securityConditionNotSatisfied)
                } else {
                    XCTFail("Failed: Wrong error type: \(error)")
                }
            }
        }
    }

    func testScp11bWrongPubKey() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.session(withConnection: connection).reset()

            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

            let chain = try await securityDomainSession.getCertificateBundle(scpKeyRef: scpKeyRef)
            let first: SecCertificate = chain.first!
            var trust: SecTrust?
            SecTrustCreateWithCertificates(first, SecPolicyCreateBasicX509(), &trust)
            let cert = SecTrustCopyKey(trust!)! // make sure we can read the public key

            let params = SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: cert)

            do {
                let _ = try await ManagementSession.session(withConnection: connection, scpKeyParams: params)
            } catch let SCPError.unexpectedResponse(message) {
                XCTAssert(true, "Expected: \(String(describing: message))")
                return
            } catch(let error) {
                XCTFail("Failed with: \(error)")
                return
            }
            XCTFail("Failed: Should have thrown an error")
        }
    }

    func testScp11bImport() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()

            // reset YubiKey's SCP state to the factory default
            try await SecurityDomainSession.session(withConnection: connection).reset()

            let securityDomainSession = try await SecurityDomainSession.session(withConnection: connection, scpKeyParams: Self.defaultKeyParams)

            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x02)

            // Generate a new key pair
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false
                ]
            ]
            var error: Unmanaged<CFError>?
            let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)!
            if let error = error?.takeRetainedValue() {
                XCTFail("Failed: Couldn't create key pair: \(error)")
                return
            }
            let publicKey = SecKeyCopyPublicKey(privateKey)!

            try await securityDomainSession.putKey(keyRef: scpKeyRef, privateKey: privateKey, replaceKvn: 0)

            let params = SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
            let _ = try await ManagementSession.session(withConnection: connection, scpKeyParams: params)

            XCTAssert(true, "Successfully imported key pair and authenticated")
        }
    }
}

private extension SecurityDomainSession {
    func verifyScp11bAuth() async throws {
        let keyRef = SCPKeyRef(kid: .scp11b, kvn: 0x7f)
        _ = try await generateEcKey(keyRef: keyRef, replaceKvn: 0)
        try await deleteKey(keyRef: keyRef)
    }
}
