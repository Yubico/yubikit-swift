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

// MARK: - Credential Filtering Tests

/// Tests for WebAuthn.Client.findMatchingCredential.
/// Modeled after yubikit-android's Ctap2ClientUtilsTest.FilterCredsTests.
@Suite("Credential Filtering Tests", .serialized)
struct CredentialFilteringTests {

    static let rpId = "example.com"

    @Test("Returns nil on empty list")
    func testEmptyList() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let result = try await client.findMatchingCredential(
            from: [],
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result == nil)
    }

    @Test("Finds credential in single-element list")
    func testSingleCredential() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            return .mocked(.finished(.stub(credentialId: target)))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [WebAuthn.CredentialDescriptor(id: target)]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
        #expect(callCount == 1)
    }

    @Test("Finds credential buried in list")
    func testCredentialInMiddle() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: target))) }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        var credentials = (0..<5).map { _ in WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)) }
        credentials.insert(WebAuthn.CredentialDescriptor(id: target), at: 3)

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
    }

    @Test("Returns nil when no credentials match")
    func testNoMatch() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { _ in .mocked(error: .ctapError(.noCredentials, source: .here())) }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32))]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result == nil)
    }

    @Test("Filters credentials exceeding maxCredentialIdLength")
    func testLengthFiltering() async throws {
        let shortCred = randomCredentialId(length: 32)
        let longCred = randomCredentialId(length: 129)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }
        var sentIds: [Data] = []
        mock.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(.stub(credentialId: shortCred)))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [
            WebAuthn.CredentialDescriptor(id: longCred),
            WebAuthn.CredentialDescriptor(id: shortCred),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == shortCred)
        #expect(!sentIds.contains(longCred))
    }

    @Test("Chunks credentials by maxCredentialCountInList")
    func testChunking() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 3) }
        // 10 credentials, chunk size 3:
        //   Call 1: indices 0-2 → no match
        //   Call 2: indices 3-5 → no match
        //   Call 3: indices 6-8 → found (target is at index 7)
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            if callCount < 3 {
                return .mocked(error: .ctapError(.noCredentials, source: .here()))
            }
            return .mocked(.finished(.stub(credentialId: target)))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        // 9 random credentials + target inserted at index 7 = 10 total
        var credentials = (0..<9).map { _ in WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)) }
        credentials.insert(WebAuthn.CredentialDescriptor(id: target), at: 7)

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
        #expect(callCount == 3)
    }

    @Test("Reduces chunk size on ERR_REQUEST_TOO_LARGE")
    func testRequestTooLargeRetry() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 10) }
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            if callCount == 1 {
                return .mocked(error: .ctapError(.requestTooLarge, source: .here()))
            }
            return .mocked(.finished(.stub(credentialId: target)))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        var credentials = (0..<9).map { _ in WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)) }
        credentials.append(WebAuthn.CredentialDescriptor(id: target))

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
        #expect(callCount == 2)
    }

    @Test("Multiple retries reducing chunk size progressively")
    func testRequestTooLargeMultipleRetries() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 5) }
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            if callCount < 4 {
                return .mocked(error: .ctapError(.requestTooLarge, source: .here()))
            }
            return .mocked(.finished(.stub(credentialId: target)))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        var credentials = (0..<4).map { _ in WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)) }
        credentials.append(WebAuthn.CredentialDescriptor(id: target))

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
        #expect(callCount == 4)
    }

    @Test("Re-throws ERR_REQUEST_TOO_LARGE when chunk size reaches 1")
    func testRequestTooLargeReachesMinimum() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 1) }
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            return .mocked(error: .ctapError(.requestTooLarge, source: .here()))
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32))]

        do {
            _ = try await client.findMatchingCredential(
                from: credentials,
                rpId: Self.rpId,
                cachedInfo: cachedInfo,
                token: nil
            )
            Issue.record("Should have thrown requestTooLarge")
        } catch let error {
            guard case .ctapError(let ctapError, _) = error,
                case .ctapError(.requestTooLarge, _) = ctapError
            else {
                Issue.record("Expected requestTooLarge, got \(error)")
                return
            }
        }

        #expect(callCount == 1)
    }

    @Test("ERR_REQUEST_TOO_LARGE in middle chunk")
    func testRequestTooLargeInMiddleChunk() async throws {
        let target = randomCredentialId(length: 32)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 3) }
        // Chunk 1: no creds, Chunk 2: too large then retry succeeds
        var callCount = 0
        mock.onGetAssertion = { _ in
            callCount += 1
            switch callCount {
            case 1: return .mocked(error: .ctapError(.noCredentials, source: .here()))
            case 2: return .mocked(error: .ctapError(.requestTooLarge, source: .here()))
            default: return .mocked(.finished(.stub(credentialId: target)))
            }
        }
        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        var credentials = (0..<6).map { _ in WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)) }
        credentials.insert(WebAuthn.CredentialDescriptor(id: target), at: 5)
        credentials.append(WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 32)))

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == target)
        #expect(callCount == 3)
    }
}

// MARK: - Preprocessing Tests

/// Tests for credential preprocessing (type filtering, length filtering).
/// These behaviors are tested through findMatchingCredential since preprocessing is inline.
@Suite("Credential Preprocessing Tests")
struct CredentialPreprocessingTests {

    static let rpId = "example.com"

    @Test("Filters unsupported credential types")
    func testFiltersUnsupportedType() async throws {
        let validCred = randomCredentialId(length: 32)
        let invalidTypeCred = randomCredentialId(length: 32)

        var sentIds: [Data] = []
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(.stub(credentialId: validCred)))
        }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [
            WebAuthn.CredentialDescriptor(type: "webauthn.get", id: invalidTypeCred),
            WebAuthn.CredentialDescriptor(type: "public-key", id: validCred),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result?.id == validCred)
        #expect(!sentIds.contains(invalidTypeCred))
        #expect(sentIds.contains(validCred))
    }

    @Test("Returns nil when all credentials have unsupported types")
    func testAllCredentialsFilteredByType() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        // All credentials have invalid types
        let credentials = [
            WebAuthn.CredentialDescriptor(type: "webauthn.get", id: randomCredentialId(length: 32)),
            WebAuthn.CredentialDescriptor(type: "webauthn.create", id: randomCredentialId(length: 32)),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result == nil)
    }

    @Test("Returns nil when all credentials exceed maxCredentialIdLength")
    func testAllCredentialsFilteredByLength() async throws {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        // All credentials exceed the 128-byte max
        let credentials = [
            WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 129)),
            WebAuthn.CredentialDescriptor(id: randomCredentialId(length: 200)),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result == nil)
    }

    @Test("Credential length boundaries")
    func testCredentialLengthBoundaries() async throws {
        let zero = Data()
        let atMax = randomCredentialId(length: 128)
        let overMax = randomCredentialId(length: 129)

        // Zero length - should pass through
        let mock0 = MockWebAuthnBackend()
        mock0.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }
        mock0.onGetAssertion = { _ in .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: zero))) }

        let client0 = try makeClient(mock: mock0)
        let cachedInfo0 = try await mock0.cachedInfo

        let result0 = try await client0.findMatchingCredential(
            from: [WebAuthn.CredentialDescriptor(id: zero)],
            rpId: Self.rpId,
            cachedInfo: cachedInfo0,
            token: nil
        )

        #expect(result0?.id == zero)

        // Exactly at max length - should pass through
        let mock1 = MockWebAuthnBackend()
        mock1.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }
        mock1.onGetAssertion = { _ in .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: atMax))) }

        let client1 = try makeClient(mock: mock1)
        let cachedInfo1 = try await mock1.cachedInfo

        let result1 = try await client1.findMatchingCredential(
            from: [WebAuthn.CredentialDescriptor(id: atMax)],
            rpId: Self.rpId,
            cachedInfo: cachedInfo1,
            token: nil
        )

        #expect(result1?.id == atMax)

        // One byte over max - should be filtered out
        let mock2 = MockWebAuthnBackend()
        mock2.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }

        let client2 = try makeClient(mock: mock2)
        let cachedInfo2 = try await mock2.cachedInfo

        let result2 = try await client2.findMatchingCredential(
            from: [WebAuthn.CredentialDescriptor(id: overMax)],
            rpId: Self.rpId,
            cachedInfo: cachedInfo2,
            token: nil
        )

        #expect(result2 == nil)
    }

    @Test("No max length allows all credentials")
    func testNoMaxLength() async throws {
        let shortCred = randomCredentialId(length: 32)
        let longCred = randomCredentialId(length: 256)

        var sentIds: [Data] = []
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: nil, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: shortCred)))
        }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [
            WebAuthn.CredentialDescriptor(id: shortCred),
            WebAuthn.CredentialDescriptor(id: longCred),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result != nil)
        #expect(sentIds.count == 2)
        #expect(sentIds.contains(shortCred))
        #expect(sentIds.contains(longCred))
    }

    @Test("Mixed valid and invalid credentials")
    func testMixedValidAndInvalid() async throws {
        let validCred1 = randomCredentialId(length: 32)
        let validCred2 = randomCredentialId(length: 64)
        let invalidType = randomCredentialId(length: 32)
        let tooLong = randomCredentialId(length: 256)

        var sentIds: [Data] = []
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: validCred1)))
        }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [
            WebAuthn.CredentialDescriptor(type: "webauthn.create", id: invalidType),
            WebAuthn.CredentialDescriptor(id: validCred1, transports: [.usb]),
            WebAuthn.CredentialDescriptor(id: tooLong),
            WebAuthn.CredentialDescriptor(id: validCred2),
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result != nil)
        #expect(!sentIds.contains(invalidType))
        #expect(!sentIds.contains(tooLong))
        #expect(sentIds.contains(validCred1))
        #expect(sentIds.contains(validCred2))
    }

    @Test("Strips transports from credentials")
    func testStripsTransports() async throws {
        let cred = randomCredentialId(length: 32)

        var sentDescriptors: [WebAuthn.CredentialDescriptor] = []
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(maxCredentialIdLength: 128, maxCredentialCountInList: 8) }
        mock.onGetAssertion = { params in
            sentDescriptors.append(contentsOf: params.allowList ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: cred)))
        }

        let client = try makeClient(mock: mock)
        let cachedInfo = try await mock.cachedInfo

        let credentials = [
            WebAuthn.CredentialDescriptor(id: cred, transports: [.usb, .nfc, .ble])
        ]

        let result = try await client.findMatchingCredential(
            from: credentials,
            rpId: Self.rpId,
            cachedInfo: cachedInfo,
            token: nil
        )

        #expect(result != nil)
        #expect(sentDescriptors.count == 1)
        #expect(sentDescriptors[0].id == cred)
        // Transports should be stripped (not sent to authenticator)
        #expect(sentDescriptors[0].transports == nil)
    }

    @Test("Varying max credential ID lengths")
    func testVaryingMaxCredIdLengths() async throws {
        let cred16 = randomCredentialId(length: 16)
        let cred32 = randomCredentialId(length: 32)
        let cred64 = randomCredentialId(length: 64)
        let cred128 = randomCredentialId(length: 128)

        let allCreds = [
            WebAuthn.CredentialDescriptor(id: cred16),
            WebAuthn.CredentialDescriptor(id: cred32),
            WebAuthn.CredentialDescriptor(id: cred64),
            WebAuthn.CredentialDescriptor(id: cred128),
        ]

        // Test with maxLength = 16 (only first credential)
        var sentIds: [Data] = []
        let mock1 = MockWebAuthnBackend()
        mock1.onGetInfo = { .stub(maxCredentialIdLength: 16, maxCredentialCountInList: 8) }
        mock1.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: cred16)))
        }
        let client1 = try makeClient(mock: mock1)
        _ = try await client1.findMatchingCredential(
            from: allCreds,
            rpId: Self.rpId,
            cachedInfo: try await mock1.cachedInfo,
            token: nil
        )
        #expect(sentIds.count == 1)
        #expect(sentIds.contains(cred16))

        // Test with maxLength = 32 (first two credentials)
        sentIds = []
        let mock2 = MockWebAuthnBackend()
        mock2.onGetInfo = { .stub(maxCredentialIdLength: 32, maxCredentialCountInList: 8) }
        mock2.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: cred16)))
        }
        let client2 = try makeClient(mock: mock2)
        _ = try await client2.findMatchingCredential(
            from: allCreds,
            rpId: Self.rpId,
            cachedInfo: try await mock2.cachedInfo,
            token: nil
        )
        #expect(sentIds.count == 2)

        // Test with maxLength = 64 (first three credentials)
        sentIds = []
        let mock3 = MockWebAuthnBackend()
        mock3.onGetInfo = { .stub(maxCredentialIdLength: 64, maxCredentialCountInList: 8) }
        mock3.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: cred16)))
        }
        let client3 = try makeClient(mock: mock3)
        _ = try await client3.findMatchingCredential(
            from: allCreds,
            rpId: Self.rpId,
            cachedInfo: try await mock3.cachedInfo,
            token: nil
        )
        #expect(sentIds.count == 3)

        // Test with maxLength = 255 (all credentials)
        sentIds = []
        let mock4 = MockWebAuthnBackend()
        mock4.onGetInfo = { .stub(maxCredentialIdLength: 255, maxCredentialCountInList: 8) }
        mock4.onGetAssertion = { params in
            sentIds.append(contentsOf: params.allowList?.map { $0.id } ?? [])
            return .mocked(.finished(CTAP2.GetAssertion.Response.stub(credentialId: cred16)))
        }
        let client4 = try makeClient(mock: mock4)
        _ = try await client4.findMatchingCredential(
            from: allCreds,
            rpId: Self.rpId,
            cachedInfo: try await mock4.cachedInfo,
            token: nil
        )
        #expect(sentIds.count == 4)
    }
}

// MARK: - Helpers

private func makeClient(
    mock: MockWebAuthnBackend,
    rpId: String = "example.com"
) throws -> WebAuthn.Client {
    WebAuthn.Client(
        backend: mock,
        origin: try WebAuthn.Origin("https://\(rpId)"),
        allowedExtensions: .all,
        isPublicSuffix: { _ in false }
    )
}

private func randomCredentialId(length: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: length)
    _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
    return Data(bytes)
}
