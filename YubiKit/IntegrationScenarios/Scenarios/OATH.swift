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
public enum OATHScenario: CaseIterable {

    case chunkedData
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
    case lockedListRejected
    case response
    case hmacSha256
    case hmacSha512
    case totpSha1_59
    case hotpSha1

    public var scenario: Scenario { definition }

    private var definition: Scenario {
        switch self {
        // MARK: - Functions
        case .chunkedData:
            return Scenario(
                "OATH.Calculate.chunkedData",
                "calculateCredentialCodes reassembles a response that spans multiple frames",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await populatedOATHSession(context)
                for n in 0...14 {
                    let template = OATHSession.CredentialTemplate(
                        type: .totp(),
                        algorithm: .sha1,
                        secret: base32Decoded("abba"),
                        issuer: "Yubico-\(n)",
                        name: "test@yubico.com",
                        digits: 6
                    )
                    try await session.addCredential(template: template)
                }
                let result = try await session.calculateCredentialCodes()
                context.expectEqual(result.count, 20, "expected 5 populated + 15 added credentials")
            }
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
        // MARK: - Password lock
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
                requirements: Requirements(capabilities: [.oath])
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
                        "expected securityConditionNotSatisfied (0x6982) while locked"
                    )
                }
                // Unlocking restores access.
                try await session.unlock(password: oathPassword)
                let credentials = try await session.listCredentials()
                context.expectEqual(credentials.count, 5, "expected 5 credentials after unlocking")
            }
        // MARK: - RFC vectors
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
        // RFC 4231 HMAC-SHA256 vector 1 (key = 0x0b×20, message = "Hi There"):
        // calculateCredentialResponse returns the full-length HMAC digest.
        case .hmacSha256:
            return Scenario(
                "OATH.Vector.hmacSha256",
                "calculateCredentialResponse matches the RFC 4231 HMAC-SHA256 vector",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha256,
                    secret: Data(repeating: 0x0b, count: 20),
                    issuer: "RFC4231",
                    name: "hmacSha256",
                    digits: 6
                )
                let credential = try await session.addCredential(template: template)
                let response = try await session.calculateCredentialResponse(
                    for: credential.id,
                    challenge: Data("Hi There".utf8)
                )
                let expected = Data(hexString: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")!
                context.expectEqual(response, expected, "HMAC-SHA256 response should match RFC 4231 vector 1")
            }
        // RFC 4231 HMAC-SHA512 vector 1. SHA-512 OATH credentials need firmware ≥ 4.3.1.
        case .hmacSha512:
            return Scenario(
                "OATH.Vector.hmacSha512",
                "calculateCredentialResponse matches the RFC 4231 HMAC-SHA512 vector",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("4.3.1"))
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha512,
                    secret: Data(repeating: 0x0b, count: 20),
                    issuer: "RFC4231",
                    name: "hmacSha512",
                    digits: 6
                )
                let credential = try await session.addCredential(template: template)
                let response = try await session.calculateCredentialResponse(
                    for: credential.id,
                    challenge: Data("Hi There".utf8)
                )
                let expected = Data(
                    hexString: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                        + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
                )!
                context.expectEqual(response, expected, "HMAC-SHA512 response should match RFC 4231 vector 1")
            }
        // RFC 6238 TOTP vector (key = ASCII "12345678901234567890", SHA1, 8 digits): at T0+59s the
        // 30-second step is 1, giving 94287082.
        case .totpSha1_59:
            return Scenario(
                "OATH.Vector.totpSha1_59",
                "calculateCredentialCode matches the RFC 6238 TOTP-SHA1 vector at t=59",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: Data("12345678901234567890".utf8),
                    issuer: "RFC6238",
                    name: "totpSha1",
                    digits: 8
                )
                let credential = try await session.addCredential(template: template)
                let code = try await session.calculateCredentialCode(
                    for: credential,
                    timestamp: Date(timeIntervalSince1970: 59)
                )
                context.expectEqual(code.code, "94287082", "TOTP-SHA1 code at t=59 should match RFC 6238")
            }
        // RFC 4226 HOTP vectors (key = ASCII "12345678901234567890", SHA1, 6 digits): each calculate
        // advances the moving factor, so successive calls walk the published counter values.
        case .hotpSha1:
            return Scenario(
                "OATH.Vector.hotpSha1",
                "successive calculateCredentialCode calls match the RFC 4226 HOTP-SHA1 vectors",
                requirements: Requirements(capabilities: [.oath])
            ) { context in
                let session = try await freshOATHSession(context)
                let template = OATHSession.CredentialTemplate(
                    type: .hotp(),
                    algorithm: .sha1,
                    secret: Data("12345678901234567890".utf8),
                    issuer: "RFC4226",
                    name: "hotpSha1",
                    digits: 6
                )
                let credential = try await session.addCredential(template: template)
                let first = try await session.calculateCredentialCode(for: credential)
                context.expectEqual(first.code, "755224", "HOTP code at counter 0 should match RFC 4226")
                let second = try await session.calculateCredentialCode(for: credential)
                context.expectEqual(second.code, "287082", "HOTP code at counter 1 should match RFC 4226")
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
        guard let cleanup = try? await OATHSession.makeSession(connection: connection, scpKeyParams: scp) else {
            return
        }
        try? await cleanup.reset()
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
