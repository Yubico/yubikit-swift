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

import CryptoKit
import Foundation
import Testing

@testable import YubiKit

// MARK: - SCP 11a
@Suite("SCP11a Full Stack Tests", .serialized)
struct SCP11aFullStackTests {

    @Test("SCP11a authentication")
    func authenticate() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11a not supported on this YubiKey")
                return
            }
            let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: 0x03)

            // first we load keys using SCP03
            var securityDomainSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: self.defaultKeyParams
            )
            let scpKeyParams = try await securityDomainSession.loadKeys(scpKeyRef)

            // then we reauthenticate using 11a
            securityDomainSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scpKeyParams
            )

            // delete the previously loaded keys
            try await securityDomainSession.deleteKey(for: scpKeyRef)

            #expect(true, "Successfully authenticated using SCP11a")
        }
    }

    @Test("SCP11a allow list")
    func allowList() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11a not supported on this YubiKey")
                return
            }
            let connection = try await TestableConnection.shared()

            // Reset YubiKey SCP state to factory defaults
            try await SecurityDomainSession.makeSession(connection: connection).reset()

            let kvn: UInt8 = 0x05
            let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: kvn)
            let oceRef = SCPKeyRef(kid: 0x10, kvn: kvn)

            // Load SCP‑11a keys using SCP03, then switch to SCP‑11a
            var sdSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: self.defaultKeyParams
            )
            let scpKeyParams = try await sdSession.loadKeys(scpKeyRef)
            sdSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scpKeyParams
            )

            // Store an allow‑list with two valid OCE serial numbers
            let serials: [Data] = [
                Data([
                    0x7f, 0x49, 0x71, 0xb0, 0xad, 0x51, 0xf8, 0x4c, 0x9d, 0xa9,
                    0x92, 0x8b, 0x2d, 0x5f, 0xef, 0x5e, 0x16, 0xb2, 0x92, 0x0a,
                ]),
                Data([
                    0x6b, 0x90, 0x02, 0x88, 0x00, 0x90, 0x9f, 0x9f, 0xfc, 0xd6,
                    0x41, 0x34, 0x69, 0x33, 0x24, 0x27, 0x48, 0xfb, 0xe9, 0xad,
                ]),
            ]
            try await sdSession.putAllowlist(for: oceRef, serials: serials)

            // Clean‑up – delete the loaded SCP‑11a keys
            try await sdSession.deleteKey(for: scpKeyRef)

            #expect(true, "Successfully configured allow‑list for SCP11a")
        }
    }

    @Test("SCP11a allow list blocked")
    func allowListBlocked() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11a not supported on this YubiKey")
                return
            }

            let kvn: UInt8 = 0x03
            let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: kvn)
            let oceRef = SCPKeyRef(kid: 0x10, kvn: kvn)

            let scp03KeyParams = try await importScp03Key(connection: connection)

            // Establish an SCP03 session
            var sdSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scp03KeyParams
            )

            // Free space if an SCP11b key is present
            try? await sdSession.deleteKey(for: SCPKeyRef(kid: .scp11b, kvn: 0x01))

            // Load SCP‑11a keys and obtain parameters for future auth
            let scpKeyParams = try await sdSession.loadKeys(scpKeyRef)

            // Populate allow‑list with blocking serials (1‑5)
            let blockedSerials: [Data] = (1...5).map { Data([UInt8($0)]) }
            try await sdSession.putAllowlist(for: oceRef, serials: blockedSerials)

            // Attempt SCP‑11a authentication – should fail due to allow‑list
            do {
                _ = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpKeyParams
                )
                Issue.record("Authentication should have been blocked by allow‑list")
            } catch {
                if case let SCPError.wrapped(inner) = error,
                    let rsp = inner as? ResponseError
                {
                    #expect(rsp.responseStatus.rawStatus == 0x6640)
                } else {
                    Issue.record("Unexpected error: \(error)")
                }
            }

            // reset allow‑list
            sdSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scp03KeyParams
            )
            try await sdSession.putAllowlist(for: oceRef, serials: [])

            // Authentication should now succeed
            _ = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scpKeyParams
            )

            #expect(true, "Allow‑list correctly blocked and then allowed SCP11a authentication")
        }
    }

    private func importScp03Key(connection: SmartCardConnection) async throws -> SCPKeyParams {
        let scp03Ref = SCPKeyRef(kid: 0x01, kvn: 0x01)

        let staticKeys = StaticKeys(
            enc: .random(length: 16),
            mac: .random(length: 16),
            dek: .random(length: 16)
        )

        let session = try await SecurityDomainSession.makeSession(
            connection: connection,
            scpKeyParams: self.defaultKeyParams
        )
        try await session.putStaticKeys(staticKeys, for: scp03Ref, replacing: 0)

        return try SCP03KeyParams(keyRef: scp03Ref, staticKeys: staticKeys)
    }
}

// MARK: - SCP 11b
@Suite("SCP11b Full Stack Tests", .serialized)
struct SCP11bFullStackTests {

    @Test("SCP11b authentication")
    func authenticate() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11b not supported on this YubiKey")
                return
            }

            let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

            let chain = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
            let leaf: X509Cert = chain.last!
            _ = leaf.publicKey  // make sure we can read the public key

            do {
                try await securityDomainSession.verifyScp11bAuth()
            } catch {
                if case let SCPError.wrapped(error) = error, let error = error as? ResponseError {
                    #expect(error.responseStatus.status == .securityConditionNotSatisfied)
                } else {
                    Issue.record("Failed: Wrong error type: \(error)")
                }
            }
        }
    }

    @Test("SCP11b wrong public key")
    func wrongPubKey() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11b not supported on this YubiKey")
                return
            }

            let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

            let chain = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
            let first: X509Cert = chain.first!
            guard case let .ec(publicKey) = first.publicKey! else {
                Issue.record("Expected EC public key")
                return
            }

            let params = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)

            do {
                let _ = try await ManagementSession.makeSession(connection: connection, scpKeyParams: params)
            } catch let SCPError.unexpectedResponse(message) {
                #expect(true, "Expected: \(String(describing: message))")
                return
            } catch (let error) {
                Issue.record("Failed with: \(error)")
                return
            }
            Issue.record("Failed: Should have thrown an error")
        }
    }

    @Test("SCP11b import key")
    func importKey() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11b not supported on this YubiKey")
                return
            }

            let securityDomainSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: self.defaultKeyParams
            )

            let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x02)

            let privateKey = EC.PrivateKey.random(curve: .secp256r1)!

            let publicKey = privateKey.publicKey

            try await securityDomainSession.putPrivateKey(privateKey, for: scpKeyRef, replacing: 0)

            let params = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
            let _ = try await ManagementSession.makeSession(connection: connection, scpKeyParams: params)

            #expect(true, "Successfully imported key pair and authenticated")
        }
    }
}

// MARK: - SCP 11c
@Suite("SCP11c Full Stack Tests", .serialized)
struct SCP11cFullStackTests {

    @Test("SCP11c authentication")
    func authenticate() async throws {
        try await runSCPTest { version in
            guard version >= Version(withString: "5.7.2")! else {
                reportSkip(reason: "SCP11c not supported on this YubiKey")
                return
            }

            let scpKeyRef = SCPKeyRef(kid: .scp11c, kvn: 0x03)

            // first we load keys using SCP03
            var securityDomainSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: self.defaultKeyParams
            )
            let scpKeyParams = try await securityDomainSession.loadKeys(scpKeyRef)

            // then we reauthenticate using 11c
            securityDomainSession = try await SecurityDomainSession.makeSession(
                connection: connection,
                scpKeyParams: scpKeyParams
            )

            // delete the previously loaded keys
            do {
                try await securityDomainSession.deleteKey(for: scpKeyRef)
            } catch {
                if case let SCPError.wrapped(error) = error, let error = error as? ResponseError {
                    #expect(error.responseStatus.status == .securityConditionNotSatisfied)
                } else {
                    Issue.record("Failed: Wrong error type: \(error)")
                }
            }
        }
    }
}

// MARK: - Helpers
extension SecurityDomainSession {
    fileprivate func verifyScp11bAuth() async throws {
        let keyRef = SCPKeyRef(kid: .scp11b, kvn: 0x7f)
        _ = try await generateECKey(for: keyRef, replacing: 0)
        try await deleteKey(for: keyRef)
    }

    fileprivate func loadKeys(_ sessionRef: SCPKeyRef) async throws -> SCP11KeyParams! {
        // Generate an ephemeral EC key on the YubiKey and retrieve its public half for ECDH
        let publicKey = try await generateECKey(for: sessionRef, replacing: 0)

        // Prepare a key reference on the device for storing the CA public key
        let oceRef = SCPKeyRef(kid: 0x10, kvn: sessionRef.kvn)

        // Upload the CA public key to the YubiKey so it can verify signatures
        let ca = Scp11TestData.caCert
        guard case let .ec(certificatePublicKey) = ca.publicKey! else {
            Issue.record("Failed to extract EC public key from CA certificate")
            return nil
        }
        try await putPublicKey(certificatePublicKey, for: oceRef, replacing: 0)

        // Extract the CA certificate's Subject Key Identifier for issuer referencing
        let ski = Insecure.SHA1.hash(data: certificatePublicKey.uncompressedPoint).data

        // Store the CA issuer identifier on the YubiKey
        try await putCAIssuer(for: oceRef, ski: ski)

        let ka = Scp11TestData.kaCert

        let ecka = Scp11TestData.eckaCert

        let sk = Scp11TestData.secretKey

        // Return all parameters needed for establishing an SCP11 session
        return try SCP11KeyParams(
            keyRef: sessionRef,
            pkSdEcka: publicKey,
            oceKeyRef: oceRef,
            skOceEcka: sk,
            certificates: [ka, ecka]
        )
    }
}
