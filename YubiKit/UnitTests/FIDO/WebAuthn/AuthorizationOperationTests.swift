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

@Suite("WebAuthn Authorization Operation Tests")
struct AuthorizationOperationTests {

    @Test(
        "Required and preferred UV use a configured PIN",
        arguments: [
            WebAuthn.UserVerificationPreference.required, .preferred,
        ]
    )
    func configuredPIN(preference: WebAuthn.UserVerificationPreference) throws {
        let info = try Self.info(options: ["clientPin": true])
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: true)

        #expect(try operation.requiresUserVerification(info: info, preference: preference, permissions: .getAssertion))
    }

    @Test("Registration's UV exemption applies only to non-resident credentials", arguments: [false, true])
    func registrationExemption(residentKey: Bool) throws {
        let info = try Self.info(options: ["clientPin": true, "makeCredUvNotRqd": true])
        let operation = WebAuthn.Authorization.Operation.makeCredential(residentKey: residentKey)

        #expect(
            try operation.requiresUserVerification(
                info: info,
                preference: .discouraged,
                permissions: [.makeCredential, .getAssertion]
            ) == residentKey
        )
    }

    @Test("Non-resident registration requires UV without the authenticator exemption")
    func registrationWithoutExemption() throws {
        let info = try Self.info(options: ["clientPin": true])
        let operation = WebAuthn.Authorization.Operation.makeCredential(residentKey: false)

        #expect(
            try operation.requiresUserVerification(info: info, preference: .discouraged, permissions: .makeCredential)
        )
    }

    @Test("Always UV overrides discouraged authentication")
    func forcedUV() throws {
        let info = try Self.info(options: ["clientPin": true, "alwaysUv": true])
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: true)

        #expect(
            try operation.requiresUserVerification(info: info, preference: .discouraged, permissions: .getAssertion)
        )
    }

    @Test("Large-blob writes require UV only when configured", arguments: [false, true])
    func largeBlobWrite(pinConfigured: Bool) throws {
        let info = try Self.info(options: ["clientPin": pinConfigured])
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: true)

        #expect(
            try operation.requiresUserVerification(
                info: info,
                preference: .discouraged,
                permissions: [.getAssertion, .largeBlobWrite]
            ) == pinConfigured
        )
    }

    @Test("Preferred UV reports an unset PIN")
    func unconfiguredPIN() throws {
        let info = try Self.info(options: ["clientPin": false])
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: true)

        #expect {
            try operation.requiresUserVerification(info: info, preference: .preferred, permissions: .getAssertion)
        } throws: { error in
            guard let error = error as? WebAuthn.ClientError, case .pinNotSet = error else { return false }
            return true
        }
    }

    @Test(
        "Unavailable UV without PIN support reports notSupported",
        arguments: [
            ([:], .required),
            (["uv": false], .preferred),
            (["alwaysUv": true], .discouraged),
        ] as [([String: Bool], WebAuthn.UserVerificationPreference)]
    )
    func unavailableUV(options: [String: Bool], preference: WebAuthn.UserVerificationPreference) throws {
        let info = try Self.info(options: options)
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: true)

        #expect {
            try operation.requiresUserVerification(info: info, preference: preference, permissions: .getAssertion)
        } throws: { error in
            guard let error = error as? WebAuthn.ClientError, case .notSupported = error else { return false }
            return true
        }
    }

    @Test("Discouraged resident registration does not demand unconfigured UV")
    func unconfiguredRegistration() throws {
        let info = try Self.info(options: ["clientPin": false])
        let operation = WebAuthn.Authorization.Operation.makeCredential(residentKey: true)

        #expect(
            try !operation.requiresUserVerification(info: info, preference: .discouraged, permissions: .makeCredential)
        )
    }

    @Test("Preferred authentication proceeds when UV is unsupported")
    func unsupportedPreferredUV() throws {
        let info = try Self.info(options: [:])
        let operation = WebAuthn.Authorization.Operation.getAssertion(hasAllowList: false)

        #expect(
            try !operation.requiresUserVerification(info: info, preference: .preferred, permissions: .getAssertion)
        )
    }

    private static func info(options: [String: Bool]) throws -> CTAP2.GetInfo.Response {
        let optionsMap = [CBOR.Value: CBOR.Value](
            uniqueKeysWithValues: options.map { (.textString($0.key), .boolean($0.value)) }
        )
        return try #require(
            CTAP2.GetInfo.Response(
                cbor: .map([
                    .int(0x01): .array([.textString("FIDO_2_1")]),
                    .int(0x03): .byteString(Data(repeating: 0, count: 16)),
                    .int(0x04): .map(optionsMap),
                ])
            )
        )
    }
}
