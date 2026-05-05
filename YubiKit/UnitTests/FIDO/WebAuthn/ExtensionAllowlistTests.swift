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

@Suite("Extension Allowlist Tests")
struct ExtensionAllowlistTests {

    @Test("Empty allowlist drops every extension on build + parse")
    func testEmptyAllowlist() async throws {
        let mock = MockWebAuthnBackend()

        let (mcInputs, mcPrf, mcPreviewSign, mcLargeBlob) = try await mock.buildMakeCredentialExtensions(
            .init(
                prf: .enable,
                credProtect: .init(policy: .userVerificationRequired),
                credBlob: Data([0xAA]),
                minPinLength: true,
                largeBlob: .required,
                credProps: true,
                thirdPartyPayment: .init(isPayment: true)
            ),
            allowedExtensions: []
        )
        #expect(mcInputs.isEmpty && mcPrf == nil && mcPreviewSign == nil && mcLargeBlob == false)

        let regOutputs = try await mock.parseRegistrationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobRequested: true,
            credPropsRk: true,
            allowedExtensions: []
        )
        let authOutputs = try await mock.parseAuthenticationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobOutput: nil,
            allowedExtensions: []
        )

        // Exhaustive: a new Identifier case forces a new arm here, which forces
        // wiring the allowlist filter in Backend+Extensions.swift before this test passes.
        for id in WebAuthn.Extension.Identifier.allCases {
            switch id {
            case .prf:
                #expect(regOutputs.prf == nil)
                #expect(authOutputs.prf == nil)
            case .credProtect:
                #expect(regOutputs.credProtect == nil)
            case .credBlob:
                #expect(regOutputs.credBlob == nil)
                #expect(authOutputs.credBlob == nil)
            case .credProps:
                #expect(regOutputs.credProps == nil)
            case .largeBlob:
                #expect(regOutputs.largeBlob == nil)
                #expect(authOutputs.largeBlob == nil)
            case .minPinLength:
                #expect(regOutputs.minPinLength == nil)
            case .thirdPartyPayment:
                #expect(regOutputs.thirdPartyPayment == nil)
                #expect(authOutputs.thirdPartyPayment == nil)
            case .previewSign:
                #expect(regOutputs.previewSign == nil)
                #expect(authOutputs.previewSign == nil)
            }
        }
    }

    @Test("Specific allowlist surfaces only listed extensions")
    func testSpecificAllowlist() async throws {
        let mock = MockWebAuthnBackend()

        let outputs = try await mock.parseRegistrationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobRequested: false,
            credPropsRk: true,
            allowedExtensions: [.credProps]
        )
        #expect(outputs.credBlob == nil)
        #expect(outputs.minPinLength == nil)
        #expect(outputs.credProps?.rk == true)
    }
}

// MARK: - CBOR-encoded authenticator-data helpers

private func authData(extensions: [CBOR.Value: CBOR.Value]) -> Data {
    var data = Data(count: 32)  // rpIdHash
    data.append(0x81)  // flags: UP + ED
    data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount
    data.append(CBOR.Value.map(extensions).encode())
    return data
}

extension CTAP2.MakeCredential.Response {
    fileprivate static func stubWithExtensions() -> CTAP2.MakeCredential.Response {
        let response: [CBOR.Value: CBOR.Value] = [
            .int(0x01): .textString("none"),
            .int(0x02): .byteString(
                authData(extensions: [
                    .textString("credBlob"): .boolean(true),
                    .textString("minPinLength"): .int(4),
                    .textString("thirdPartyPayment"): .boolean(true),
                ])
            ),
            .int(0x03): .map([:]),
        ]
        return CTAP2.MakeCredential.Response(cbor: try! CBOR.Value.map(response).encode().decode()!)!
    }
}

extension CTAP2.GetAssertion.Response {
    fileprivate static func stubWithExtensions() -> CTAP2.GetAssertion.Response {
        let data = authData(extensions: [
            .textString("credBlob"): .byteString(Data([0x11, 0x22])),
            .textString("thirdPartyPayment"): .boolean(true),
        ])
        return Self(
            credential: WebAuthn.CredentialDescriptor(id: Data([0xAA])),
            authenticatorData: WebAuthn.AuthenticatorData(data: data)!,
            signature: Data([0x30, 0x44]),
            user: nil,
            numberOfCredentials: 1,
            userSelected: nil,
            largeBlobKey: nil
        )
    }
}
