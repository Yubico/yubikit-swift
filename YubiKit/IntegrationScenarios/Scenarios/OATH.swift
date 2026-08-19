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
import YubiKit

/// OATH application scenarios.
public enum OATHScenario: CaseIterable, ScenarioSuite {

    case credentials
    case allCodes
    case codes
    case numericPrefixName
    case credentialRename
    case noIssuer
    case toExisting
    case credentialDelete
    case sha512
    case touch
    case populatedReset
    case unlock
    case wrong
    case deleteAccessKey
    case deleteAccessKeyRejectedOnFIPS
    case lockedListRejected
    case lockedCalculateRejected
    case lockedCalculateAllRejected
    case lockedDeleteRejected
    case lockedRenameRejected
    case toExistingDistinct
    case response
    case maxCredentials
    case unicodeName

    public var scenario: Scenario { definition }

    private var definition: Scenario {
        switch self {
        // MARK: - TestFunctions
        case .credentials:
            return Scenario(
                "OATH.List.credentials",
                "listCredentials returns the populated credentials with the expected labels and types",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                let credentials = try await session.listCredentials()
                try context.require(credentials.count == 5, "expected 5 credentials, got \(credentials.count)")
                context.expect(credentials[0].label == "TOTP SHA1:6 digits, 30 sec", "credential 0 label")
                context.expect(credentials[0].type.period == 30.0, "credential 0 period")
                context.expect(credentials[1].label == "TOTP SHA256:6 digits, 30 sec", "credential 1 label")
                context.expect(credentials[2].type.period == 15.0, "credential 2 period")
                context.expect(credentials[2].label == "15/TOTP SHA1 15s no issuer", "credential 2 label")
                context.expect(
                    credentials[3].label == "TOTP SHA256:requires touch, 6 digits, 30 sec",
                    "credential 3 label"
                )
                context.expect(credentials[4].label == "HOTP SHA1:6 digits, counter = 0", "credential 4 label")
                context.expect(credentials[4].type.counter == 0, "credential 4 counter")
            }
        case .allCodes:
            return Scenario(
                "OATH.Calculate.allCodes",
                "calculateCredentialCodes plus manual touch/HOTP calculation yields the expected codes",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                let timestamp = Date(timeIntervalSince1970: 0)
                let result = try await session.calculateCredentialCodes(timestamp: timestamp)
                var codes: [OATHSession.Code] = []
                for (credential, code) in result {
                    if let code {
                        codes.append(code)
                    } else {
                        if credential.requiresTouch {
                            context.touch("Touch the YubiKey to calculate the touch-protected code")
                        }
                        codes.append(try await session.calculateCredentialCode(for: credential, timestamp: timestamp))
                    }
                }
                try context.require(codes.count == 5, "expected 5 codes, got \(codes.count)")
                context.expect(codes[0].code == "659165", "code 0")
                context.expect(codes[1].code == "807284", "code 1")
                context.expect(codes[2].code == "29659165", "code 2")
                context.expect(codes[3].code == "807284", "code 3")
                context.expect(codes[4].code == "659165", "code 4")
            }
        case .codes:
            return Scenario(
                "OATH.Calculate.codes",
                "calculateCredentialCodes auto-calculates only the standard-period TOTP codes",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                let result = try await session.calculateCredentialCodes(timestamp: Date(timeIntervalSince1970: 0))
                let codes = result.compactMap { _, code in code?.code }
                try context.require(
                    codes.count == 3,
                    "expected 3 auto-calculated codes, not touch/HOTP ones"
                )
                context.expect(codes[0] == "659165", "code 0")
                context.expect(codes[1] == "807284", "code 1")
                context.expect(codes[2] == "29659165", "code 2")
            }
        case .numericPrefixName:
            return Scenario(
                "OATH.Add.numericPrefixName",
                "a credential whose issuer and name begin with digits can be added and calculated",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba2"),
                    issuer: "15 Issuer",
                    name: "15 begin with numbers",
                    digits: 6
                )
                try await session.addCredential(template: template)
                let credential = try context.require(
                    try await session.listCredentials().first,
                    "Failed to add credential"
                )
                let code = try await session.calculateCredentialCode(for: credential)
                context.log("Got code: \(code.code)")
                context.expect(!code.code.isEmpty, "calculated code should not be empty")
            }
        case .credentialRename:
            return Scenario(
                "OATH.Rename.credential",
                "renameCredential updates the account name and issuer",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: "Original Issuer",
                    name: "Original Name",
                    digits: 6
                )
                try await session.addCredential(template: template)
                let credential = try context.require(
                    try await session.listCredentials().first,
                    "expected a credential after adding one"
                )
                try await session.renameCredential(credential, newName: "New Name", newIssuer: "New Issuer")
                let renamed = try context.require(
                    try await session.listCredentials().first,
                    "expected the renamed credential"
                )
                context.expect(renamed.name == "New Name", "name should be updated")
                context.expect(renamed.issuer == "New Issuer", "issuer should be updated")
            }
        case .noIssuer:
            return Scenario(
                "OATH.Rename.noIssuer",
                "renameCredential can clear the issuer",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: "Original Issuer",
                    name: "Original Name",
                    digits: 6
                )
                try await session.addCredential(template: template)
                let credential = try context.require(
                    try await session.listCredentials().first,
                    "expected a credential after adding one"
                )
                try await session.renameCredential(credential, newName: "New Name", newIssuer: nil)
                let renamed = try context.require(
                    try await session.listCredentials().first,
                    "expected the renamed credential"
                )
                context.expect(renamed.name == "New Name", "name should be updated")
                context.expect(renamed.issuer == nil, "issuer should be cleared")
            }
        case .toExisting:
            return Scenario(
                "OATH.Rename.toExisting",
                "renaming a credential onto an existing identifier is rejected",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await freshOATHSession(context)
                let sourceTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: "Source Issuer",
                    name: "Source Name",
                    digits: 6
                )
                let existingTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("baab"),
                    issuer: "Existing Issuer",
                    name: "Existing Name",
                    digits: 6
                )
                try await session.addCredential(template: sourceTemplate)
                try await session.addCredential(template: existingTemplate)

                let credentials = try await session.listCredentials()
                let source = try context.require(
                    credentials.first { $0.label == sourceTemplate.identifier },
                    "expected source credential"
                )
                _ = try context.require(
                    credentials.first { $0.label == existingTemplate.identifier },
                    "expected existing credential"
                )

                do {
                    try await session.renameCredential(
                        source,
                        newName: existingTemplate.name,
                        newIssuer: existingTemplate.issuer
                    )
                    context.record("renaming onto an existing identifier should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.log("rename onto existing identifier rejected with \(response.status)")
                }

                let after = try await session.listCredentials()
                context.expect(
                    after.contains { $0.label == sourceTemplate.identifier },
                    "source credential should keep its original identifier"
                )
                context.expect(
                    after.contains { $0.label == existingTemplate.identifier },
                    "existing credential should remain present"
                )
            }
        case .toExistingDistinct:
            return Scenario(
                "OATH.Rename.toExistingDistinct",
                "renaming a credential onto another existing credential's identifier is rejected",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await freshOATHSession(context)
                let firstTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: "Issuer One",
                    name: "Name One",
                    digits: 6
                )
                let secondTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: "Issuer Two",
                    name: "Name Two",
                    digits: 6
                )
                try await session.addCredential(template: firstTemplate)
                let second = try await session.addCredential(template: secondTemplate)
                // Renaming the second credential onto the first's existing identifier must fail.
                do {
                    try await session.renameCredential(second, newName: "Name One", newIssuer: "Issuer One")
                    context.record("renaming onto another credential's existing identifier should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.log("rename onto distinct existing identifier rejected with \(response.status)")
                }
            }
        case .credentialDelete:
            return Scenario(
                "OATH.Delete.credential",
                "deleteCredential removes a single credential",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                let credentials = try await session.listCredentials()
                let first = try context.require(credentials.first, "expected at least one credential")
                try await session.deleteCredential(first)
                let remaining = try await session.listCredentials()
                context.expectEqual(credentials.count, remaining.count + 1, "exactly one credential should be removed")
            }
        case .sha512:
            return Scenario(
                "OATH.Feature.sha512",
                "a SHA-512 credential can be added and reports the SHA-512 algorithm",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("4.3.1"))
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha512,
                    secret: base32Decoded("abba2"),
                    issuer: "SHA-512",
                    name: "FeatureTest"
                )
                try await session.addCredential(template: template)
                let credential = try context.require(
                    try await session.listCredentials().first,
                    "expected the SHA-512 credential after adding it"
                )
                let algorithm = try context.require(
                    credential.hashAlgorithm,
                    "credential should report a hash algorithm"
                )
                context.expect(algorithm == .sha512, "algorithm should be SHA-512")
                let id = try context.require(
                    String(data: credential.id, encoding: .utf8),
                    "credential id should be UTF-8"
                )
                context.expectEqual(id, template.identifier, "credential id should match the template identifier")
            }
        case .touch:
            return Scenario(
                "OATH.Feature.touch",
                "a touch-required credential is reported as requiring touch and yields no auto code",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("4.2.0"))
            ) { context in
                let session = try await freshOATHSession(context)
                let touchTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha256,
                    secret: base32Decoded("abba2"),
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: true
                )
                try await session.addCredential(template: touchTemplate)
                let (touchCredential, touchCode) = try context.require(
                    try await session.calculateCredentialCodes().first,
                    "expected a calculated entry for the touch credential"
                )
                let touchId = try context.require(
                    String(data: touchCredential.id, encoding: .utf8),
                    "credential id should be UTF-8"
                )
                context.expectEqual(touchId, touchTemplate.identifier, "touch credential id should match the template")
                context.expect(touchCredential.requiresTouch, "credential should report requiresTouch")
                context.expect(touchCode == nil, "touch credential should not be auto-calculated")
                try await session.deleteCredential(touchCredential)

                let noTouchTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha256,
                    secret: base32Decoded("abba2"),
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: false
                )
                try await session.addCredential(template: noTouchTemplate)
                let (noTouchCredential, noTouchCode) = try context.require(
                    try await session.calculateCredentialCodes().first,
                    "expected a calculated entry for the non-touch credential"
                )
                let noTouchId = try context.require(
                    String(data: noTouchCredential.id, encoding: .utf8),
                    "credential id should be UTF-8"
                )
                context.expectEqual(
                    noTouchId,
                    noTouchTemplate.identifier,
                    "no-touch credential id should match the template"
                )
                context.expect(noTouchCode != nil, "no-touch credential should be auto-calculated")
                context.expect(!noTouchCredential.requiresTouch, "credential should not require touch")
            }
        case .populatedReset:
            return Scenario(
                "OATH.Cleanup.populatedReset",
                "the OATH application resets and re-populates with the standard test accounts",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                _ = try await populatedOATHSession(context)
                context.log("reset and re-populated with the standard test accounts")
            }
        // MARK: - TestLockPreventsAccess
        case .unlock:
            return Scenario(
                "OATH.Password.unlock",
                "a password-protected application can be unlocked and listed",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context, password: oathPassword)
                try await session.unlock(password: oathPassword)
                let credentials = try await session.listCredentials()
                context.expectEqual(credentials.count, 5, "expected 5 credentials after unlocking")
            }
        case .wrong:
            return Scenario(
                "OATH.Password.wrong",
                "unlocking with the wrong password fails with invalidPassword",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context, password: oathPassword)
                do {
                    try await session.unlock(password: "abc123")
                    context.record("unlocking with the wrong password should have failed")
                } catch {
                    if case OATHSessionError.invalidPassword = error {
                        context.log("Got expected error: \(error)")
                    } else {
                        context.record("Got unexpected error: \(error)")
                    }
                }
            }
        case .deleteAccessKey:
            return Scenario(
                "OATH.Password.deleteAccessKey",
                "deleteAccessKey removes the password so a fresh session needs no unlock",
                requirements: Requirements(capabilities: [.oath], excludesFIPS: true)
            ) { context in
                let session = try await populatedOATHSession(context, password: oathPassword)
                try await session.unlock(password: oathPassword)
                try await session.deleteAccessKey()
                // Re-select OATH from scratch (via a Management select in between) to prove the access key is gone.
                let connection = try await context.smartCardConnection()
                let scp = try await context.scpKeyParams()
                _ = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
                let reopened = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
                let credentials = try await reopened.listCredentials()
                context.expectEqual(
                    credentials.count,
                    5,
                    "expected 5 credentials without unlocking after deleting the access key"
                )
            }
        // FIPS OATH must stay access-key protected once approved.
        case .deleteAccessKeyRejectedOnFIPS:
            return Scenario(
                "OATH.Password.deleteAccessKeyRejectedOnFIPS",
                "a FIPS OATH application rejects access-key removal",
                requirements: Requirements(capabilities: [.oath], requiresFIPS: true)
            ) { context in
                let session = try await populatedOATHSession(context, password: oathPassword)
                try await session.unlock(password: oathPassword)
                do {
                    try await session.deleteAccessKey()
                    context.record("FIPS OATH should reject deleting the access key")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .conditionsNotSatisfied,
                        "expected conditionsNotSatisfied (0x6985) rejecting OATH access-key removal, got \(response.status)"
                    )
                }
            }
        case .lockedListRejected:
            return Scenario(
                "OATH.Password.lockedListRejected",
                "a locked OATH application rejects listing until it is unlocked",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context, password: oathPassword)
                do {
                    _ = try await session.listCredentials()
                    context.record("listing a locked OATH application should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "sw should be SECURITY_CONDITION_NOT_SATISFIED (0x6982)"
                    )
                }
                // Unlocking restores access.
                try await session.unlock(password: oathPassword)
                let credentials = try await session.listCredentials()
                context.expectEqual(credentials.count, 5, "expected 5 credentials after unlocking")
            }
        case .lockedCalculateRejected:
            return Scenario(
                "OATH.Password.lockedCalculateRejected",
                "a locked OATH application rejects calculating a single credential until it is unlocked",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let (session, credential) = try await lockedOATHSession(context)
                do {
                    _ = try await session.calculateCredentialCode(for: credential)
                    context.record("calculating on a locked OATH application should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "sw should be SECURITY_CONDITION_NOT_SATISFIED (0x6982)"
                    )
                }
            }
        case .lockedCalculateAllRejected:
            return Scenario(
                "OATH.Password.lockedCalculateAllRejected",
                "a locked OATH application rejects calculating all credentials until it is unlocked",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let (session, _) = try await lockedOATHSession(context)
                do {
                    _ = try await session.calculateCredentialCodes()
                    context.record("calculateCredentialCodes on a locked OATH application should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "sw should be SECURITY_CONDITION_NOT_SATISFIED (0x6982)"
                    )
                }
            }
        case .lockedDeleteRejected:
            return Scenario(
                "OATH.Password.lockedDeleteRejected",
                "a locked OATH application rejects deleting a credential until it is unlocked",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let (session, credential) = try await lockedOATHSession(context)
                do {
                    try await session.deleteCredential(credential)
                    context.record("deleting on a locked OATH application should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "sw should be SECURITY_CONDITION_NOT_SATISFIED (0x6982)"
                    )
                }
            }
        case .lockedRenameRejected:
            return Scenario(
                "OATH.Password.lockedRenameRejected",
                "a locked OATH application rejects renaming a credential until it is unlocked",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.3.0"))
            ) { context in
                let (session, credential) = try await lockedOATHSession(context)
                do {
                    try await session.renameCredential(credential, newName: "renamed", newIssuer: nil)
                    context.record("renaming on a locked OATH application should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "sw should be SECURITY_CONDITION_NOT_SATISFIED (0x6982)"
                    )
                }
            }
        // MARK: - RFC vectors
        // calculateCredentialResponse op as TestHmacVectors, which uses RFC 4231 vectors)
        case .response:
            return Scenario(
                "OATH.Calculate.response",
                "calculateCredentialResponse matches the RFC 2202 HMAC-SHA1 test vector",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                // secret = base32("BMFQWCYL…") = 20 bytes of 0x0b, the RFC 2202 HMAC-SHA1 test key.
                let url = URL(
                    string:
                        "otpauth://totp/Yubico:test@yubico.com?secret=BMFQWCYLBMFQWCYLBMFQWCYLBMFQWCYL"
                        + "&issuer=test-create-and-calculate-response&algorithm=SHA1&digits=7&counter=30"
                )!
                let template = try OATHSession.CredentialTemplate(url: url)
                let credential = try await session.addCredential(template: template)
                let response = try await session.calculateCredentialResponse(
                    for: credential.id,
                    challenge: Data("Hi There".utf8)
                )
                let expected = Data([
                    0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
                    0xf1,
                    0x46, 0xbe, 0x00,
                ])
                context.expectEqual(response, expected, "HMAC-SHA1 response should match RFC 2202 vector 1")
            }
        // MARK: - TestOATH (cli)
        case .maxCredentials:
            return Scenario(
                "OATH.Add.maxCredentials",
                "the OATH application accepts the firmware-dependent credential limit and rejects one more",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                // Credential limit depends on firmware: 32 before 5.7.0, 64 from 5.7.0 onward.
                let version = await session.version
                let limit = version >= Version("5.7.0")! ? 64 : 32
                context.log("device firmware \(version), credential limit \(limit)")
                for i in 0..<limit {
                    let template = OATHSession.CredentialTemplate(
                        type: .totp(),
                        algorithm: .sha1,
                        secret: base32Decoded("abba"),
                        issuer: nil,
                        name: "test\(i)",
                        digits: 6
                    )
                    try await session.addCredential(template: template)
                    let count = try await session.listCredentials().count
                    context.expectEqual(count, i + 1, "credential count should grow by one after adding test\(i)")
                }
                // Adding one beyond the limit must fail (storage full).
                let overflow = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: nil,
                    name: "test\(limit)",
                    digits: 6
                )
                do {
                    _ = try await session.addCredential(template: overflow)
                    context.record("adding beyond the max should have failed")
                } catch OATHSessionError.failedResponse(let response, _) {
                    context.log("storage full correctly rejected with \(response.status)")
                }
            }
        case .unicodeName:
            return Scenario(
                "OATH.Add.unicodeName",
                "a credential with a unicode name can be added, calculated, listed and deleted",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: base32Decoded("abba"),
                    issuer: nil,
                    name: "😃",
                    digits: 6
                )
                let credential = try await session.addCredential(template: template)
                let code = try await session.calculateCredentialCode(for: credential)
                context.expect(!code.code.isEmpty, "calculated code should not be empty")
                let listed = try await session.listCredentials()
                context.expect(listed.contains { $0.name == "😃" }, "listed credentials should contain the unicode name")
                try await session.deleteCredential(credential)
                let remaining = try await session.listCredentials()
                context.expect(
                    !remaining.contains { $0.name == "😃" },
                    "the unicode credential should be gone after deletion"
                )
            }
        }
    }
}

// MARK: - Parameterized RFC test-vector families

extension OATHScenario {

    /// RFC test vectors: HMAC (RFC 4231 SHA256/512), TOTP (RFC 6238 SHA1/256/512 × timestamps × digit
    /// counts), and HOTP (RFC 4226 SHA1 × digit counts).
    static var parameterizedScenarios: [Scenario] {
        hmacVectorScenarios + totpVectorScenarios + hotpVectorScenarios
    }

    // RFC 4231 §2: a TOTP credential is used purely as an HMAC key, and the full-length response is
    // compared to the published digest. Short keys (`Jefe`) are zero-padded by CredentialTemplate,
    // which leaves the HMAC unchanged.
    private struct HMACVector: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let algorithm: OATHSession.HashAlgorithm
        let secret: Data
        let challenge: Data
        let expected: Data

        init(
            _ idSuffix: String,
            _ algorithm: OATHSession.HashAlgorithm,
            secret: Data,
            challenge: Data,
            expected: String
        ) {
            self.idSuffix = idSuffix
            self.displayName = "calculateCredentialResponse matches the RFC 4231 HMAC vector \(idSuffix)"
            self.requirements = Requirements(
                capabilities: [.oath],
                minVersion: algorithm == .sha512 ? Version("4.3.1") : nil
            )
            self.algorithm = algorithm
            self.secret = secret
            self.challenge = challenge
            self.expected = Data(hexString: expected)!
        }
    }

    private static var hmacVectorScenarios: [Scenario] {
        let key0b = Data(repeating: 0x0b, count: 20)
        let keyAa = Data(repeating: 0xaa, count: 20)
        let keyInc = Data(hexString: "0102030405060708090a0b0c0d0e0f10111213141516171819")!
        let hiThere = Data("Hi There".utf8)
        let jefe = Data("what do ya want for nothing?".utf8)
        let dd = Data(repeating: 0xdd, count: 50)
        let cd = Data(repeating: 0xcd, count: 50)
        let vectors: [HMACVector] = [
            HMACVector(
                "tc1.sha256",
                .sha256,
                secret: key0b,
                challenge: hiThere,
                expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            ),
            HMACVector(
                "tc1.sha512",
                .sha512,
                secret: key0b,
                challenge: hiThere,
                expected: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ),
            HMACVector(
                "tc2.sha256",
                .sha256,
                secret: Data("Jefe".utf8),
                challenge: jefe,
                expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            ),
            HMACVector(
                "tc2.sha512",
                .sha512,
                secret: Data("Jefe".utf8),
                challenge: jefe,
                expected: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                    + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
            HMACVector(
                "tc3.sha256",
                .sha256,
                secret: keyAa,
                challenge: dd,
                expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
            ),
            HMACVector(
                "tc3.sha512",
                .sha512,
                secret: keyAa,
                challenge: dd,
                expected: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                    + "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
            ),
            HMACVector(
                "tc4.sha256",
                .sha256,
                secret: keyInc,
                challenge: cd,
                expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
            ),
            HMACVector(
                "tc4.sha512",
                .sha512,
                secret: keyInc,
                challenge: cd,
                expected: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                    + "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
            ),
        ]
        return Scenario.parameterized("OATH.Vector.HMAC", over: vectors) { context, vector in
            let session = try await freshOATHSession(context)
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: vector.algorithm,
                secret: vector.secret,
                issuer: "RFC4231",
                name: vector.idSuffix,
                digits: 6
            )
            let credential = try await session.addCredential(template: template)
            let response = try await session.calculateCredentialResponse(
                for: credential.id,
                challenge: vector.challenge
            )
            context.expectEqual(response, vector.expected, "HMAC \(vector.idSuffix) should match RFC 4231")
        }
    }

    // RFC 6238 Appendix B: SHA1/256/512 seeds at two reference timestamps, each checked at 6 and 8
    // digits (the 8-digit value is the suffix of the 6-digit one).
    private struct TOTPVector: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let algorithm: OATHSession.HashAlgorithm
        let secret: Data
        let timestamp: TimeInterval
        let expected8: String
        let digits: UInt8
    }

    private static var totpVectorScenarios: [Scenario] {
        let keys: [(String, OATHSession.HashAlgorithm, Data)] = [
            ("sha1", .sha1, Data("12345678901234567890".utf8)),
            ("sha256", .sha256, Data("12345678901234567890123456789012".utf8)),
            ("sha512", .sha512, Data(("12345678901234567890123456789012" + "34567890123456789012345678901234").utf8)),
        ]
        let table: [(TimeInterval, [String: String])] = [
            (59, ["sha1": "94287082", "sha256": "46119246", "sha512": "90693936"]),
            (1_111_111_109, ["sha1": "07081804", "sha256": "68084774", "sha512": "25091201"]),
        ]
        var vectors: [TOTPVector] = []
        for (label, algorithm, secret) in keys {
            let minVersion = algorithm == .sha512 ? Version("4.3.1") : nil
            for (timestamp, expected) in table {
                for digits in [UInt8(6), UInt8(8)] {
                    let seconds = Int(timestamp)
                    let name =
                        "calculateCredentialCode matches the RFC 6238 TOTP \(label) vector at t=\(seconds), \(digits) digits"
                    vectors.append(
                        TOTPVector(
                            idSuffix: "\(label).t\(seconds).d\(digits)",
                            displayName: name,
                            requirements: Requirements(capabilities: [.oath], minVersion: minVersion),
                            algorithm: algorithm,
                            secret: secret,
                            timestamp: timestamp,
                            expected8: expected[label]!,
                            digits: digits
                        )
                    )
                }
            }
        }
        return Scenario.parameterized("OATH.Vector.TOTP", over: vectors) { context, vector in
            let session = try await freshOATHSession(context)
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: vector.algorithm,
                secret: vector.secret,
                issuer: "RFC6238",
                name: "totp.\(vector.idSuffix)",
                digits: vector.digits
            )
            let credential = try await session.addCredential(template: template)
            let code = try await session.calculateCredentialCode(
                for: credential,
                timestamp: Date(timeIntervalSince1970: vector.timestamp)
            )
            context.expectEqual(UInt8(code.code.count), vector.digits, "TOTP code length should match the digit count")
            context.expect(
                vector.expected8.hasSuffix(code.code),
                "TOTP \(vector.idSuffix) should match RFC 6238 (\(vector.expected8))"
            )
        }
    }

    // RFC 4226 Appendix D: the HOTP-SHA1 counter sequence, walked by successive calculate calls, at
    // both 6 and 8 digits.
    private struct HOTPVector: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let digits: UInt8

        init(digits: UInt8) {
            self.idSuffix = "sha1.d\(digits)"
            self.displayName =
                "successive calculateCredentialCode calls match the RFC 4226 HOTP-SHA1 vectors, \(digits) digits"
            self.requirements = Requirements(capabilities: [.oath])
            self.digits = digits
        }
    }

    private static var hotpVectorScenarios: [Scenario] {
        let sequence8 = [
            "84755224", "94287082", "37359152", "26969429", "40338314",
            "68254676", "18287922", "82162583", "73399871", "45520489",
        ]
        let vectors = [HOTPVector(digits: 6), HOTPVector(digits: 8)]
        return Scenario.parameterized("OATH.Vector.HOTP", over: vectors) { context, vector in
            let session = try await freshOATHSession(context)
            let template = OATHSession.CredentialTemplate(
                type: .hotp(),
                algorithm: .sha1,
                secret: Data("12345678901234567890".utf8),
                issuer: "RFC4226",
                name: "hotp.\(vector.digits)",
                digits: vector.digits
            )
            let credential = try await session.addCredential(template: template)
            for expected8 in sequence8 {
                let code = try await session.calculateCredentialCode(for: credential)
                context.expectEqual(
                    UInt8(code.code.count),
                    vector.digits,
                    "HOTP code length should match the digit count"
                )
                context.expect(expected8.hasSuffix(code.code), "HOTP code should match RFC 4226 (\(expected8))")
            }
        }
    }
}

// MARK: - Suite-private helpers

private let oathPassword = "password"

/// Reset OATH, then re-select so password derivation sees the new salt.
private func freshOATHSession(_ context: Scenario.Context) async throws -> OATHSession {
    let connection = try await context.smartCardConnection()
    let scp = try await context.scpKeyParams()
    try await OATHSession.makeSession(connection: connection, scpKeyParams: scp).reset()
    await context.addTeardown {
        let cleanup = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
        try await cleanup.reset()
    }
    return try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
}

private func populatedOATHSession(
    _ context: Scenario.Context,
    password: String? = nil
) async throws -> OATHSession {
    var session = try await freshOATHSession(context)
    for template in standardOATHCredentials() {
        try await session.addCredential(template: template)
    }

    if let password {
        try await session.setPassword(password)
        // Select another applet so the next OATH SELECT reports the locked state.
        let connection = try await context.smartCardConnection()
        let scp = try await context.scpKeyParams()
        _ = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
        session = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
    }

    return session
}

/// Add a single credential, password-lock the OATH application, then re-select so the next session
/// reports the locked state. Returns the locked session along with the `Credential` captured before
/// locking (a locked session cannot list, so the credential must be obtained up front).
private func lockedOATHSession(
    _ context: Scenario.Context
) async throws -> (OATHSession, OATHSession.Credential) {
    let session = try await freshOATHSession(context)
    let template = OATHSession.CredentialTemplate(
        type: .totp(),
        algorithm: .sha1,
        secret: base32Decoded("abba"),
        issuer: "Locked Issuer",
        name: "Locked Name",
        digits: 6
    )
    let credential = try await session.addCredential(template: template)
    try await session.setPassword(oathPassword)
    // Select another applet so the next OATH SELECT reports the locked state.
    let connection = try await context.smartCardConnection()
    let scp = try await context.scpKeyParams()
    _ = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
    let locked = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
    return (locked, credential)
}

private func standardOATHCredentials() -> [OATHSession.CredentialTemplate] {
    let secret = base32Decoded("abba")
    return [
        OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha1,
            secret: secret,
            issuer: "TOTP SHA1",
            name: "6 digits, 30 sec",
            digits: 6
        ),
        OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha256,
            secret: secret,
            issuer: "TOTP SHA256",
            name: "6 digits, 30 sec",
            digits: 6
        ),
        OATHSession.CredentialTemplate(
            type: .totp(period: 15),
            algorithm: .sha1,
            secret: secret,
            issuer: nil,
            name: "TOTP SHA1 15s no issuer",
            digits: 8
        ),
        OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha256,
            secret: secret,
            issuer: "TOTP SHA256",
            name: "requires touch, 6 digits, 30 sec",
            digits: 6,
            requiresTouch: true
        ),
        OATHSession.CredentialTemplate(
            type: .hotp(),
            algorithm: .sha1,
            secret: secret,
            issuer: "HOTP SHA1",
            name: "6 digits, counter = 0",
            digits: 6
        ),
    ]
}

/// Minimal RFC 4648 base32 decoder.
private func base32Decoded(_ string: String) -> Data {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var lookup: [Character: Int] = [:]
    for (index, character) in alphabet.enumerated() {
        lookup[character] = index
    }
    var bitBuffer = 0
    var bitCount = 0
    var output = Data()
    for character in string.uppercased() {
        guard let value = lookup[character] else { continue }
        bitBuffer = (bitBuffer << 5) | value
        bitCount += 5
        if bitCount >= 8 {
            bitCount -= 8
            output.append(UInt8((bitBuffer >> bitCount) & 0xff))
        }
    }
    return output
}
