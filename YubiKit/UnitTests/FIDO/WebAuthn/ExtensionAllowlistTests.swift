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

// MARK: - Extension Allowlist Tests

@Suite("Extension Allowlist Tests")
struct ExtensionAllowlistTests {

    @Test("Empty allowlist blocks all extension inputs on both make + assertion")
    func testEmptyAllowlistBlocksBuild() async throws {
        let mock = MockWebAuthnBackend()

        let registrationInputs = WebAuthn.Extension.RegistrationInputs(
            prf: .enable,
            credProtect: .init(policy: .userVerificationRequired),
            credBlob: Data([0xAA, 0xBB]),
            minPinLength: true,
            largeBlob: .required,
            credProps: true,
            thirdPartyPayment: .enable
        )
        let (mcInputs, mcPrf, _, mcLargeBlob) = try await mock.buildMakeCredentialExtensions(
            registrationInputs,
            allowedExtensions: []
        )
        #expect(mcInputs.isEmpty)
        #expect(mcPrf == nil)
        #expect(mcLargeBlob == false)

        let assertionInputs = WebAuthn.Extension.AuthenticationInputs(
            prf: .init(eval: .init(first: Data(repeating: 0x01, count: 32))),
            getCredBlob: true,
            largeBlob: .read,
            thirdPartyPayment: .init(isPayment: true)
        )
        let (gaInputs, gaPrf, _, gaLargeBlob) = try await mock.buildGetAssertionExtensions(
            assertionInputs,
            allowCredentials: [],
            selectedCredentialId: nil,
            allowedExtensions: []
        )
        #expect(gaInputs.isEmpty)
        #expect(gaPrf == nil)
        #expect(gaLargeBlob == nil)
    }

    @Test("Empty allowlist drops echoed extension outputs on both make + assertion")
    func testEmptyAllowlistDropsParse() async throws {
        let mock = MockWebAuthnBackend()

        let regOutputs = try await mock.parseRegistrationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobRequested: false,
            credPropsRk: true,
            allowedExtensions: []
        )
        #expect(regOutputs.credBlob == nil)
        #expect(regOutputs.minPinLength == nil)
        #expect(regOutputs.credProps == nil)

        let authOutputs = try await mock.parseAuthenticationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobOutput: nil,
            allowedExtensions: []
        )
        #expect(authOutputs.credBlob == nil)
    }

    @Test("Specific allowlist surfaces only listed extensions")
    func testSpecificAllowlistFilters() async throws {
        let mock = MockWebAuthnBackend()

        let outputs = try await mock.parseRegistrationOutputs(
            from: .stubWithExtensions(),
            prf: nil,
            previewSign: nil,
            largeBlobRequested: false,
            credPropsRk: true,
            allowedExtensions: [.thirdPartyPayment, .credProps]
        )
        #expect(outputs.credBlob == nil)
        #expect(outputs.minPinLength == nil)
        #expect(outputs.credProps?.rk == true)
    }
}

// MARK: - CBOR-encoded authenticator-data helpers

extension CTAP2.MakeCredential.Response {
    fileprivate static func stubWithExtensions() -> CTAP2.MakeCredential.Response {
        let extensions: [CBOR.Value: CBOR.Value] = [
            .textString("credBlob"): .boolean(true),
            .textString("minPinLength"): .int(4),
            .textString("thirdPartyPayment"): .boolean(true),
        ]
        var authData = Data()
        authData.append(Data(repeating: 0, count: 32))  // rpIdHash
        authData.append(0x81)  // flags: UP + ED
        authData.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount
        authData.append(CBOR.Value.map(extensions).encode())

        let response: [CBOR.Value: CBOR.Value] = [
            .int(0x01): .textString("none"),
            .int(0x02): .byteString(authData),
            .int(0x03): .map([:]),
        ]
        let decoded: CBOR.Value? = try! CBOR.Value.map(response).encode().decode()
        return CTAP2.MakeCredential.Response(cbor: decoded!)!
    }
}

extension CTAP2.GetAssertion.Response {
    fileprivate static func stubWithExtensions() -> CTAP2.GetAssertion.Response {
        let extensions: [CBOR.Value: CBOR.Value] = [
            .textString("credBlob"): .byteString(Data([0x11, 0x22])),
            .textString("thirdPartyPayment"): .boolean(true),
        ]
        var authData = Data()
        authData.append(Data(repeating: 0, count: 32))
        authData.append(0x81)
        authData.append(contentsOf: [0x00, 0x00, 0x00, 0x01])
        authData.append(CBOR.Value.map(extensions).encode())

        return Self(
            credential: WebAuthn.CredentialDescriptor(id: Data([0xAA])),
            authenticatorData: WebAuthn.AuthenticatorData(data: authData)!,
            signature: Data([0x30, 0x44]),
            user: nil,
            numberOfCredentials: 1,
            userSelected: nil,
            largeBlobKey: nil
        )
    }
}
