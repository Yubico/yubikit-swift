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
import CryptoTokenKit
import Foundation
import YubiKit

/// Secure Channel Protocol scenarios.
enum SCPScenario: CaseIterable, ScenarioSuite {

    case defaultKeys
    case importKeySCP03
    case deleteKey
    case replaceKey
    case wrongKey
    case authenticateSCP11a
    case allowlist
    case allowlistBlocked
    case authenticateSCP11b
    case wrongPublicKey
    case importKeySCP11b
    case authenticateSCP11c
    case keyInformation
    case supportedCAIdentifiers
    case certificateBundle
    case cardRecognitionData
    case resetRestoresDefaultKeys

    var scenario: Scenario { definition }

    private var definition: Scenario {
        switch self {
        // MARK: - TestScp03
        case .defaultKeys:
            return Scenario(
                "SCP.SCP03.defaultKeys",
                "default SCP03 static keys authenticate a Management session",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let management = try await Management.Session.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                let info = try await management.getDeviceInfo()
                context.expect(info.version.major >= 4, "authenticated SCP03 session returns a device info")
            }
        case .importKeySCP03:
            return Scenario(
                "SCP.SCP03.importKey",
                "importing a new SCP03 key set replaces the default keys",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let session = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )

                let sk = Data([
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                ])
                let staticKeys = StaticKeys(enc: sk, mac: sk, dek: sk)
                let keyRef = SCPKeyRef(kid: .scp03, kvn: 0x01)
                let params = try SCP03KeyParams(keyRef: keyRef, staticKeys: staticKeys)

                try await session.putStaticKeys(staticKeys, for: keyRef, replacing: 0)

                let newSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: params
                )
                _ = try await newSession.getKeyInformation()
                context.log("imported SCP03 keys authenticate")

                // the imported set must displace the default keys, not coexist with them
                do {
                    _ = try await SecurityDomainSession.makeSession(
                        connection: connection,
                        scpKeyParams: scpDefaultKeyParams
                    )
                    context.record("default keys should no longer authenticate after import")
                } catch {
                    context.log("default keys correctly rejected after import")
                }
            }
        case .deleteKey:
            return Scenario(
                "SCP.SCP03.deleteKey",
                "deleting SCP03 keys (incl. the final key) revokes authentication",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let staticKeys1 = StaticKeys(
                    enc: randomBytes(count: 16),
                    mac: randomBytes(count: 16),
                    dek: randomBytes(count: 16)
                )
                let staticKeys2 = StaticKeys(
                    enc: randomBytes(count: 16),
                    mac: randomBytes(count: 16),
                    dek: randomBytes(count: 16)
                )

                let keyRef1 = SCPKeyRef(kid: .scp03, kvn: 0x10)
                let keyRef2 = SCPKeyRef(kid: .scp03, kvn: 0x55)
                let params1 = try SCP03KeyParams(keyRef: keyRef1, staticKeys: staticKeys1)
                let params2 = try SCP03KeyParams(keyRef: keyRef2, staticKeys: staticKeys2)

                // Import keyRef1 under the default keys, then chain: keyRef1 imports keyRef2 so both exist.
                var session = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                try await session.putStaticKeys(staticKeys1, for: keyRef1, replacing: 0)

                session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                try await session.putStaticKeys(staticKeys2, for: keyRef2, replacing: 0)

                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)

                session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
                try await session.deleteKey(for: keyRef1)

                do {
                    _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                    context.record("authentication with the deleted first key should fail")
                } catch {
                    context.log("deleted first key correctly rejected")
                }

                session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)

                // deleteLast is required for the final key — the Security Domain refuses to leave itself keyless otherwise.
                try await session.deleteKey(for: keyRef2, deleteLast: true)

                do {
                    _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
                    context.record("authentication with the deleted last key should fail")
                } catch {
                    context.log("deleted last key correctly rejected")
                }
            }
        case .replaceKey:
            return Scenario(
                "SCP.SCP03.replaceKey",
                "replacing an SCP03 key revokes the old key version",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let sk1 = StaticKeys(
                    enc: randomBytes(count: 16),
                    mac: randomBytes(count: 16),
                    dek: randomBytes(count: 16)
                )
                let sk2 = StaticKeys(
                    enc: randomBytes(count: 16),
                    mac: randomBytes(count: 16),
                    dek: randomBytes(count: 16)
                )

                let keyRef1 = SCPKeyRef(kid: .scp03, kvn: 0x10)
                let keyRef2 = SCPKeyRef(kid: .scp03, kvn: 0x55)

                let params1 = try SCP03KeyParams(keyRef: keyRef1, staticKeys: sk1)
                let params2 = try SCP03KeyParams(keyRef: keyRef2, staticKeys: sk2)

                var session = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                try await session.putStaticKeys(sk1, for: keyRef1, replacing: 0)

                // Replace via keyRef1's own KVN, so keyRef2 supersedes keyRef1 rather than coexisting.
                session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                try await session.putStaticKeys(sk2, for: keyRef2, replacing: keyRef1.kvn)

                do {
                    _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params1)
                    context.record("the replaced key should no longer authenticate")
                } catch {
                    context.log("replaced key correctly rejected")
                }

                session = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params2)
                _ = try await session.getKeyInformation()
                context.log("replacement key authenticates")
            }
        case .wrongKey:
            return Scenario(
                "SCP.SCP03.wrongKey",
                "a wrong SCP03 key fails to authenticate and to send secure commands",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let sk = StaticKeys(
                    enc: randomBytes(count: 16),
                    mac: randomBytes(count: 16),
                    dek: randomBytes(count: 16)
                )
                let keyRef = SCPKeyRef(kid: .scp03, kvn: 0x01)
                let params = try SCP03KeyParams(keyRef: keyRef, staticKeys: sk)

                do {
                    _ = try await SecurityDomainSession.makeSession(connection: connection, scpKeyParams: params)
                    context.record("authenticating with a wrong key should fail")
                } catch {
                    context.log("wrong key correctly rejected")
                }

                // Even if session creation slips through, a secure command must still be rejected.
                do {
                    let session = try? await SecurityDomainSession.makeSession(
                        connection: connection,
                        scpKeyParams: params
                    )
                    if let session {
                        _ = try await session.getKeyInformation()
                        context.record("should not be able to send a secure command with a wrong key")
                    }
                } catch {
                    context.log("secure command correctly rejected")
                }

                // A failed authentication must not lock out the still-valid default key.
                let session = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                _ = try await session.getKeyInformation()
                context.log("default key authenticates after a wrong-key failure")
            }
        // MARK: - TestScp11
        // MARK: SCP11a
        case .authenticateSCP11a:
            return Scenario(
                "SCP.SCP11a.authenticate",
                "loads SCP11a keys over SCP03 then re-authenticates with SCP11a",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: 0x03)

                // SCP11 keys must be loaded over an already-authenticated channel; bootstrap via SCP03,
                // then re-authenticate over SCP11a using the freshly loaded key set.
                var securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                let scpKeyParams = try await loadScp11Keys(
                    context,
                    session: securityDomainSession,
                    sessionRef: scpKeyRef
                )

                securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpKeyParams
                )
                try await securityDomainSession.deleteKey(for: scpKeyRef)

                context.log("successfully authenticated using SCP11a")
            }
        case .allowlist:
            return Scenario(
                "SCP.SCP11a.allowlist",
                "stores an OCE allow-list of valid serial numbers for SCP11a",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let kvn: UInt8 = 0x05
                let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: kvn)
                let oceRef = SCPKeyRef(kid: 0x10, kvn: kvn)

                // Bootstrap SCP11a over SCP03 (SCP11 keys can't be loaded over SCP11), then re-authenticate.
                var securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                let scpKeyParams = try await loadScp11Keys(
                    context,
                    session: securityDomainSession,
                    sessionRef: scpKeyRef
                )
                securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpKeyParams
                )

                // Allow-list two OCE certificate serial numbers that match the loaded chain, so auth stays permitted.
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
                try await securityDomainSession.putAllowlist(for: oceRef, serials: serials)

                try await securityDomainSession.deleteKey(for: scpKeyRef)

                context.log("successfully configured allow-list for SCP11a")
            }
        case .allowlistBlocked:
            return Scenario(
                "SCP.SCP11a.allowlistBlocked",
                "an allow-list of non-matching serials blocks SCP11a until cleared",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let kvn: UInt8 = 0x03
                let scpKeyRef = SCPKeyRef(kid: .scp11a, kvn: kvn)
                let oceRef = SCPKeyRef(kid: 0x10, kvn: kvn)

                let scp03KeyParams = try await importScp03Key(connection: connection)

                var securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scp03KeyParams
                )

                // Free a key slot if a stale SCP11b key is present; the load below may need the space.
                try? await securityDomainSession.deleteKey(for: SCPKeyRef(kid: .scp11b, kvn: 0x01))

                let scpKeyParams = try await loadScp11Keys(
                    context,
                    session: securityDomainSession,
                    sessionRef: scpKeyRef
                )

                // Allow-list serials 1-5, none of which match the loaded OCE chain, so auth must be blocked.
                let blockedSerials: [Data] = (1...5).map { Data([UInt8($0)]) }
                try await securityDomainSession.putAllowlist(for: oceRef, serials: blockedSerials)

                do {
                    _ = try await SecurityDomainSession.makeSession(
                        connection: connection,
                        scpKeyParams: scpKeyParams
                    )
                    context.record("authentication should have been blocked by the allow-list")
                } catch {
                    if case let SCPError.failedResponse(response, _) = error {
                        context.expect(
                            response.rawStatus == 0x6640,
                            "blocked authentication should report 0x6640, got "
                                + String(format: "0x%04X", response.rawStatus)
                        )
                    } else {
                        context.record("unexpected error type: \(error)")
                    }
                }

                // An empty allow-list disables filtering entirely, re-permitting any OCE.
                securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scp03KeyParams
                )
                try await securityDomainSession.putAllowlist(for: oceRef, serials: [])

                _ = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpKeyParams
                )

                context.log("allow-list correctly blocked and then allowed SCP11a authentication")
            }
        // MARK: SCP11b
        case .authenticateSCP11b:
            return Scenario(
                "SCP.SCP11b.authenticate",
                "SCP11b reads the leaf certificate and gates unverified key generation",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

                let chain = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
                let leaf = try context.require(chain.last, "expected a non-empty certificate chain")
                context.expect(leaf.publicKey != nil, "leaf certificate exposes a public key")

                do {
                    // generate + delete an SCP11b key, which requires off-card entity verification
                    let keyRef = SCPKeyRef(kid: .scp11b, kvn: 0x7f)
                    _ = try await securityDomainSession.generateECKey(for: keyRef, replacing: 0)
                    try await securityDomainSession.deleteKey(for: keyRef)
                    context.record("unverified SCP11b key generation should have been rejected")
                } catch {
                    if case let SCPError.failedResponse(response, _) = error {
                        context.expect(
                            response.status == .securityConditionNotSatisfied,
                            "unverified SCP11b session should report securityConditionNotSatisfied"
                        )
                    } else {
                        context.record("unexpected error type: \(error)")
                    }
                }
            }
        case .wrongPublicKey:
            return Scenario(
                "SCP.SCP11b.wrongPublicKey",
                "SCP11b with the intermediate (wrong) public key fails to authenticate",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)

                let chain = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
                let first = try context.require(chain.first, "expected a non-empty certificate chain")
                guard case let .ec(publicKey) = first.publicKey else {
                    context.record("expected EC public key")
                    return
                }

                // Using the public key from the intermediate cert instead of the leaf must fail
                let params = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
                do {
                    _ = try await Management.Session.makeSession(connection: connection, scpKeyParams: params)
                } catch ManagementSessionError.responseParseError(let message, _) {
                    context.log("wrong public key correctly rejected: \(String(describing: message))")
                    return
                } catch {
                    context.record("unexpected error type: \(error)")
                    return
                }
                context.record("authentication should have thrown an error")
            }
        case .importKeySCP11b:
            return Scenario(
                "SCP.SCP11b.importKey",
                "imports a generated SCP11b key pair and authenticates with it",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )

                let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x02)

                let privateKey = try context.require(
                    EC.PrivateKey(x963: P256.Signing.PrivateKey().x963Representation, curve: .secp256r1),
                    "failed to generate a P-256 private key"
                )
                let publicKey = privateKey.publicKey

                try await securityDomainSession.putPrivateKey(privateKey, for: scpKeyRef, replacing: 0)

                let params = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
                _ = try await Management.Session.makeSession(connection: connection, scpKeyParams: params)

                context.log("successfully imported SCP11b key pair and authenticated")
            }
        // MARK: SCP11c
        case .authenticateSCP11c:
            return Scenario(
                "SCP.SCP11c.authenticate",
                "loads SCP11c keys over SCP03 and re-authenticates with SCP11c",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)

                let scpKeyRef = SCPKeyRef(kid: .scp11c, kvn: 0x03)

                // Bootstrap SCP11c over SCP03 (SCP11 keys can't be loaded over SCP11), then re-authenticate.
                var securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpDefaultKeyParams
                )
                let scpKeyParams = try await loadScp11Keys(
                    context,
                    session: securityDomainSession,
                    sessionRef: scpKeyRef
                )

                securityDomainSession = try await SecurityDomainSession.makeSession(
                    connection: connection,
                    scpKeyParams: scpKeyParams
                )

                // SCP11c gates key deletion behind additional verification, so this delete is expected to fail.
                do {
                    try await securityDomainSession.deleteKey(for: scpKeyRef)
                } catch {
                    if case let SCPError.failedResponse(response, _) = error {
                        context.expect(
                            response.status == .securityConditionNotSatisfied,
                            "SCP11c delete should report securityConditionNotSatisfied"
                        )
                    } else {
                        context.record("unexpected error type: \(error)")
                    }
                }
            }
        // MARK: - Security Domain free functions
        // MARK: Key info
        case .keyInformation:
            return Scenario(
                "SCP.SecurityDomain.keyInformation",
                "getKeyInformation returns the Security Domain key table",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let info = try await securityDomainSession.getKeyInformation()
                context.expect(info != [:], "key information should not be empty")
            }
        case .supportedCAIdentifiers:
            return Scenario(
                "SCP.SecurityDomain.supportedCAIdentifiers",
                "getSupportedCAIdentifiers reports KLOC/KLCC identifiers",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let info = try await securityDomainSession.getSupportedCAIdentifiers(kloc: true, klcc: true)
                context.expect(info != [:], "supported CA identifiers should not be empty")
            }
        // MARK: Certificates
        // Reads the SCP11b certificate bundle and uses its leaf public key to bring up an
        // SCP11b-secured Management session.
        case .certificateBundle:
            return Scenario(
                "SCP.SecurityDomain.certificateBundle",
                "getCertificateBundle yields a leaf key that authenticates SCP11b",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)
                let certificates = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
                guard let last = certificates.last, case let .ec(publicKey) = last.publicKey else {
                    context.record("expected a leaf certificate with an EC public key")
                    return
                }
                let scp11KeyParams = try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
                let management = try await Management.Session.makeSession(
                    connection: connection,
                    scpKeyParams: scp11KeyParams
                )
                let deviceInfo = try await management.getDeviceInfo()
                context.expect(deviceInfo.version.major >= 4, "device info via SCP11b should be valid")
            }
        case .cardRecognitionData:
            return Scenario(
                "SCP.SecurityDomain.cardRecognitionData",
                "getCardRecognitionData reports the expected GlobalPlatform TLV tag sequence",
                requirements: Requirements(minVersion: Version("5.7.2"), requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let data = try await securityDomainSession.getCardRecognitionData()
                let records = try context.require(
                    TKBERTLVRecord.sequenceOfRecords(from: data),
                    "card recognition data should be a TLV sequence"
                )
                let leadingTags = records.prefix(5).map { $0.tag }
                context.expectEqual(
                    leadingTags,
                    [0x06, 0x60, 0x63, 0x64, 0x64],
                    "card recognition data should begin with the GlobalPlatform tag sequence"
                )
            }
        // MARK: Reset
        // Verifies the default SCP03 key set (KID 0x01 / KVN 0xFF) is present in getKeyInformation after reset.
        case .resetRestoresDefaultKeys:
            return Scenario(
                "SCP.SecurityDomain.resetRestoresDefaultKeys",
                "resetting the Security Domain restores the default SCP03 key set",
                requirements: Requirements(requiresSCP: true)
            ) { context in
                let connection = try await resetSecurityDomain(context)
                let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
                let info = try await securityDomainSession.getKeyInformation()
                context.expect(
                    info[SCPKeyRef(kid: .scp03, kvn: 0xFF)] != nil,
                    "key information should contain the default SCP03 key set (KID 0x01 / KVN 0xFF) after a reset"
                )
            }
        }
    }
}

// MARK: - Suite-private helpers

/// Factory-default SCP03 key set.
private let scpDefaultKeyParams: SCP03KeyParams = {
    let defaultKeyRef = SCPKeyRef(kid: .scp03, kvn: 0xff)
    return try! SCP03KeyParams(keyRef: defaultKeyRef, staticKeys: StaticKeys.defaultKeys())
}()

private func resetSecurityDomain(_ context: Scenario.Context) async throws -> any SmartCardConnection {
    let connection = try await context.smartCardConnection()
    try await SecurityDomainSession.makeSession(connection: connection).reset()
    await context.addTeardown {
        let cleanup = try await SecurityDomainSession.makeSession(connection: connection)
        try await cleanup.reset()
    }
    return connection
}

/// Imports a fresh random SCP03 key set.
private func importScp03Key(connection: any SmartCardConnection) async throws -> SCP03KeyParams {
    let scp03Ref = SCPKeyRef(kid: 0x01, kvn: 0x01)
    let staticKeys = StaticKeys(enc: randomBytes(count: 16), mac: randomBytes(count: 16), dek: randomBytes(count: 16))

    let session = try await SecurityDomainSession.makeSession(
        connection: connection,
        scpKeyParams: scpDefaultKeyParams
    )
    try await session.putStaticKeys(staticKeys, for: scp03Ref, replacing: 0)

    return try SCP03KeyParams(keyRef: scp03Ref, staticKeys: staticKeys)
}

/// Loads an SCP11a/c key set and returns its auth parameters.
private func loadScp11Keys(
    _ context: Scenario.Context,
    session: SecurityDomainSession,
    sessionRef: SCPKeyRef
) async throws -> SCP11KeyParams {
    let publicKey = try await session.generateECKey(for: sessionRef, replacing: 0)

    let oceRef = SCPKeyRef(kid: 0x10, kvn: sessionRef.kvn)

    let ca = Scp11TestData.caCert
    guard case let .ec(certificatePublicKey) = ca.publicKey else {
        context.record("expected EC public key from CA certificate")
        throw RequireFailure()
    }
    try await session.putPublicKey(certificatePublicKey, for: oceRef, replacing: 0)

    let ski = Data(Insecure.SHA1.hash(data: certificatePublicKey.x963))
    try await session.putCAIssuer(for: oceRef, ski: ski)

    return try SCP11KeyParams(
        keyRef: sessionRef,
        pkSdEcka: publicKey,
        oceKeyRef: oceRef,
        skOceEcka: Scp11TestData.secretKey,
        certificates: [Scp11TestData.kaCert, Scp11TestData.eckaCert]
    )
}

// MARK: - SCP11 test data
//
// Test vectors from yubikey-manager:
// https://github.com/Yubico/yubikey-manager/tree/main/tests/files/scp

private enum Scp11TestData {

    // cert.ca-kloc.ecdsa.pem
    static let caCert = [X509Cert](pem: caPem)![0]
    private static let caPem: String = """
        -----BEGIN CERTIFICATE-----
        MIIB2zCCAYGgAwIBAgIUSf59wIpCKOrNGNc5FMPTD9zDGVAwCgYIKoZIzj0EAwIw
        KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
        NDA1MjgwOTIyMDlaFw0yNDA2MjcwOTIyMDlaMCoxKDAmBgNVBAMMH0V4YW1wbGUg
        T0NFIFJvb3QgQ0EgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
        AASPrxfpSB/AvuvLKaCz1YTx68Xbtx8S9xAMfRGwzp5cXMdF8c7AWpUfeM3BQ26M
        h0WPvyBJKhCdeK8iVCaHyr5Jo4GEMIGBMB0GA1UdDgQWBBQxqlVmn2Bn6B8z3P0E
        /t5z5XGfPTASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjA8BgNV
        HSABAf8EMjAwMA4GDCqGSIb8a2QACgIBFDAOBgwqhkiG/GtkAAoCASgwDgYMKoZI
        hvxrZAAKAgEAMAoGCCqGSM49BAMCA0gAMEUCIHv8cgOzxq2n1uZktL9gCXSR85mk
        TieYeSoKZn6MM4rOAiEA1S/+7ez/gxDl01ztKeoHiUiW4FbEG4JUCzIITaGxVvM=
        -----END CERTIFICATE-----
        """

    // cert.ka-kloc.ecdsa.pem
    static let kaCert = [X509Cert](pem: kaPem)![0]
    private static let kaPem: String = """
        -----BEGIN CERTIFICATE-----
        MIIB8DCCAZegAwIBAgIUf0lxsK1R+EydqZKLLV/vXhaykgowCgYIKoZIzj0EAwIw
        KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
        NDA1MjgwOTIyMDlaFw0yNDA4MjYwOTIyMDlaMC8xLTArBgNVBAMMJEV4YW1wbGUg
        T0NFIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49
        AwEHA0IABMXbjb+Y33+GP8qUznrdZSJX9b2qC0VUS1WDhuTlQUfg/RBNFXb2/qWt
        h/a+Ag406fV7wZW2e4PPH+Le7EwS1nyjgZUwgZIwHQYDVR0OBBYEFJzdQCINVBES
        R4yZBN2l5CXyzlWsMB8GA1UdIwQYMBaAFDGqVWafYGfoHzPc/QT+3nPlcZ89MBIG
        A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMCwGA1UdIAEB/wQiMCAw
        DgYMKoZIhvxrZAAKAgEoMA4GDCqGSIb8a2QACgIBADAKBggqhkjOPQQDAgNHADBE
        AiBE5SpNEKDW3OehDhvTKT9g1cuuIyPdaXGLZ3iX0x0VcwIgdnIirhlKocOKGXf9
        ijkE8e+9dTazSPLf24lSIf0IGC8=
        -----END CERTIFICATE-----
        """

    // cert.oce.ecka.pem
    static let eckaCert = [X509Cert](pem: eckaPem)![0]
    private static let eckaPem: String = """
        -----BEGIN CERTIFICATE-----
        MIIBwjCCAWmgAwIBAgIUa5ACiACQn5/81kE0aTMkJ0j76a0wCgYIKoZIzj0EAwIw
        LzEtMCsGA1UEAwwkRXhhbXBsZSBPQ0UgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRl
        MB4XDTI0MDUyODA5MjIwOVoXDTI0MDgyNjA5MjIwOVowIjEgMB4GA1UEAwwXRXhh
        bXBsZSBPQ0UgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASY
        yRCUFDM7fb0iOwyaO4ayzp+vh7UhonFbCuzgYKMLHplN3r8cyQNuso0J5UqZUwVy
        llE1EAF2Pu+RlJvtnYD2o3AwbjAdBgNVHQ4EFgQU6dH0CdJ18Nzbj3vamDW/rZl7
        GvcwHwYDVR0jBBgwFoAUnN1AIg1UERJHjJkE3aXkJfLOVawwDgYDVR0PAQH/BAQD
        AgMIMBwGA1UdIAEB/wQSMBAwDgYMKoZIhvxrZAAKAgEAMAoGCCqGSM49BAMCA0cA
        MEQCIE2Fp0ybSmD5sZ6kvrpUJ14WAdHjUbUfFxXwLU4Dnn2tAiBmPMUa4DqpnnnN
        Xfx/i/gUmwCTdA+dFrc1jWYZ8qVd6Q==
        -----END CERTIFICATE-----
        """

    // sk.oce.ecka.pem
    static let secretKey = EC.PrivateKey(pem: secretKeyPem)!
    private static let secretKeyPem = """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTWGyQ5Nmm3WG0Hfc
        NhjOla4n7fzKkiDN6t4Gjngfe6yhRANCAASYyRCUFDM7fb0iOwyaO4ayzp+vh7Uh
        onFbCuzgYKMLHplN3r8cyQNuso0J5UqZUwVyllE1EAF2Pu+RlJvtnYD2
        -----END PRIVATE KEY-----
        """
}

// MARK: - PEM parsing

extension [X509Cert] {
    fileprivate init?(pem: String) {
        let regex = try! NSRegularExpression(
            pattern: "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            options: [.dotMatchesLineSeparators]
        )
        let matches = regex.matches(in: pem, options: [], range: NSRange(location: 0, length: pem.utf16.count))

        var certs: [X509Cert] = []

        for match in matches {
            if let range = Range(match.range(at: 1), in: pem) {
                let base64 = pem[range].replacingOccurrences(of: "\n", with: "")
                if let derData = Data(base64Encoded: base64) {
                    certs.append(X509Cert(der: derData))
                } else {
                    return nil
                }
            }
        }

        self = certs
    }
}

extension EC.PrivateKey {
    fileprivate init?(pem: String) {
        guard let pkcs8Key = try? P256.Signing.PrivateKey(pemRepresentation: pem) else {
            return nil
        }

        let rep = pkcs8Key.x963Representation as Data

        guard let key = EC.PrivateKey(x963: rep, curve: .secp256r1) else {
            return nil
        }

        self = key
    }
}
