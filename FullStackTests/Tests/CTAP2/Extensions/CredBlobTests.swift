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
import YubiKit

@Suite("CredBlob Full Stack Tests", .serialized)
struct CredBlobFullStackTests {

    // MARK: - Store and Retrieve

    @Test("Store Blob at MakeCredential and Retrieve at GetAssertion")
    func testStoreAndRetrieveCredBlob() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await CTAP2.Extension.CredBlob.isSupported(by: session) else {
                print("credBlob not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping (credBlob with rk requires PIN)")
                return
            }

            let rpId = "credblob-test.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let testBlob = Data("Hello from CredBlob test!".utf8)

            // 1. Create credential with credBlob extension
            session = try await reconnectWhenOverNFC()
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let credBlob = try await CTAP2.Extension.CredBlob(session: session)

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredBlob Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "blob@test.com",
                    displayName: "CredBlob Test User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [try credBlob.makeCredential.input(blob: testBlob)],
                rk: true
            )

            print("👆 Touch YubiKey: creating credential with credBlob...")
            let credential = try await session.makeCredential(parameters: makeCredParams, token: pinToken).value

            let stored = credBlob.makeCredential.output(from: credential)
            #expect(stored == true, "credBlob should indicate successful storage")
            print("✅ Credential created with credBlob stored")

            // 2. GetAssertion with credBlob extension to retrieve blob
            session = try await reconnectWhenOverNFC()
            let gaToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let credBlobGA = try await CTAP2.Extension.CredBlob(session: session)
            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                extensions: [credBlobGA.getAssertion.input()]
            )

            print("👆 Touch YubiKey: authenticating to retrieve credBlob...")
            let assertion = try await session.getAssertion(parameters: getAssertionParams, token: gaToken).value

            let retrievedBlob = credBlobGA.getAssertion.output(from: assertion)
            #expect(retrievedBlob == testBlob, "Retrieved blob should match stored blob")
            print("✅ CredBlob retrieved and verified")
        }
    }

    // MARK: - Without Extension

    @Test("GetAssertion Without CredBlob Extension Returns No Blob")
    func testGetAssertionWithoutExtension() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await CTAP2.Extension.CredBlob.isSupported(by: session) else {
                print("credBlob not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "credblob-noext.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let testBlob = Data("Blob that should not be returned".utf8)

            // 1. Create credential with credBlob
            session = try await reconnectWhenOverNFC()
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let credBlob = try await CTAP2.Extension.CredBlob(session: session)

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredBlob NoExt Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x02, count: 32),
                    name: "noext@test.com",
                    displayName: "NoExt User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [try credBlob.makeCredential.input(blob: testBlob)],
                rk: true
            )

            print("👆 Touch YubiKey: creating credential with credBlob...")
            _ = try await session.makeCredential(parameters: makeCredParams, token: pinToken).value
            print("✅ Credential created")

            // 2. GetAssertion WITHOUT credBlob extension
            session = try await reconnectWhenOverNFC()
            let gaToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            // GetAssertion without extensions
            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash
            )

            print("👆 Touch YubiKey: authenticating without credBlob extension...")
            let assertion = try await session.getAssertion(parameters: getAssertionParams, token: gaToken).value

            let credBlobGA = try await CTAP2.Extension.CredBlob(session: session)
            let retrievedBlob = credBlobGA.getAssertion.output(from: assertion)
            #expect(retrievedBlob == nil, "Blob should not be returned without extension")
            print("✅ Verified no blob returned without extension")
        }
    }

    // MARK: - Max Length Validation

    @Test("CredBlob Rejects Oversized Blob")
    func testOversizedBlobRejected() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.CredBlob.isSupported(by: session) else {
                print("credBlob not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard let maxLength = info.maxCredBlobLength else {
                print("maxCredBlobLength not available - skipping")
                return
            }

            let credBlob = try await CTAP2.Extension.CredBlob(session: session)
            let oversizedBlob = Data(repeating: 0xFF, count: Int(maxLength) + 1)

            do {
                _ = try credBlob.makeCredential.input(blob: oversizedBlob)
                Issue.record("Expected error for oversized blob")
            } catch let error as CTAP2.SessionError {
                guard case .illegalArgument = error else {
                    Issue.record("Expected illegalArgument error, got \(error)")
                    return
                }
                print("✅ Correctly rejected oversized blob (\(oversizedBlob.count) > \(maxLength) bytes)")
            }
        }
    }

}
