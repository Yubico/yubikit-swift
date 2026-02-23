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

// MARK: - Backwards Compatibility

/// This file contains deprecated API overloads for backwards compatibility.

// MARK: - Deprecated Token Type

extension CTAP2.ClientPin {
    @available(*, deprecated, renamed: "CTAP2.Token")
    public typealias Token = CTAP2.Token
}

// MARK: - Deprecated Options Types

extension CTAP2.MakeCredential.Parameters {

    /// Authenticator options for makeCredential.
    ///
    /// - Deprecated: Pass `rk` and `uv` directly to
    /// ``init(clientDataHash:rp:user:pubKeyCredParams:excludeList:extensions:rk:uv:enterpriseAttestation:)``.
    @available(*, deprecated, message: "Pass rk and uv directly to Parameters init")
    public struct Options: Sendable {
        public let rk: Bool?
        public let uv: Bool?
        public init(rk: Bool? = nil, uv: Bool? = nil) {
            self.rk = rk
            self.uv = uv
        }
    }

    @available(*, deprecated, message: "Pass rk and uv directly to Parameters init")
    public init(
        clientDataHash: Data,
        rp: WebAuthn.PublicKeyCredential.RPEntity,
        user: WebAuthn.PublicKeyCredential.UserEntity,
        pubKeyCredParams: [COSE.Algorithm],
        excludeList: [WebAuthn.PublicKeyCredential.Descriptor]? = nil,
        extensions: [CTAP2.Extension.MakeCredential.Input] = [],
        options: Options? = nil,
        enterpriseAttestation: Int? = nil
    ) {
        self.init(
            clientDataHash: clientDataHash,
            rp: rp,
            user: user,
            pubKeyCredParams: pubKeyCredParams,
            excludeList: excludeList,
            extensions: extensions,
            rk: options?.rk ?? false,
            uv: options?.uv,
            enterpriseAttestation: enterpriseAttestation
        )
    }
}

extension CTAP2.GetAssertion.Parameters {

    /// Authenticator options for getAssertion.
    ///
    /// - Deprecated: Pass `up` and `uv` directly to
    /// ``init(rpId:clientDataHash:allowList:extensions:up:uv:)``.
    @available(*, deprecated, message: "Pass up and uv directly to Parameters init")
    public struct Options: Sendable {
        public let up: Bool?
        public let uv: Bool?
        public init(up: Bool? = nil, uv: Bool? = nil) {
            self.up = up
            self.uv = uv
        }
    }

    @available(*, deprecated, message: "Pass up and uv directly to Parameters init")
    public init(
        rpId: String,
        clientDataHash: Data,
        allowList: [WebAuthn.PublicKeyCredential.Descriptor]? = nil,
        extensions: [CTAP2.Extension.GetAssertion.Input] = [],
        options: Options? = nil
    ) {
        self.init(
            rpId: rpId,
            clientDataHash: clientDataHash,
            allowList: allowList,
            extensions: extensions,
            up: options?.up,
            uv: options?.uv
        )
    }
}

// MARK: - Deprecated Session Methods

extension CTAP2.Session {

    // MARK: - MakeCredential (Deprecated requireResidentKey parameter)

    @available(*, deprecated, message: "Set rk in Parameters init instead")
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        pinToken: CTAP2.Token,
        requireResidentKey: Bool
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        var params = parameters
        params.rk = requireResidentKey
        return await makeCredential(parameters: params, token: pinToken)
    }

    // MARK: - GetAssertion (Deprecated requireUserPresence parameter)

    @available(*, deprecated, message: "Set up in Parameters init instead")
    public func getAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        pinToken: CTAP2.Token,
        requireUserPresence: Bool?
    ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        var params = parameters
        params.up = requireUserPresence
        return await getAssertion(parameters: params, token: pinToken)
    }

    // MARK: - GetAssertions Sequence (Deprecated requireUserPresence parameter)

    @available(*, deprecated, message: "Set up in Parameters init instead")
    public func getAssertions(
        parameters: CTAP2.GetAssertion.Parameters,
        pinToken: CTAP2.Token,
        requireUserPresence: Bool?
    ) async -> CTAP2.GetAssertion.Sequence {
        var params = parameters
        params.up = requireUserPresence
        return await getAssertions(parameters: params, token: pinToken)
    }

    // MARK: - Deprecated pinToken: parameter name

    @available(*, deprecated, renamed: "makeCredential(parameters:token:)")
    public func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        pinToken: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        await makeCredential(parameters: parameters, token: pinToken)
    }

    @available(*, deprecated, renamed: "getAssertion(parameters:token:)")
    public func getAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        pinToken: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        await getAssertion(parameters: parameters, token: pinToken)
    }

    @available(*, deprecated, renamed: "getAssertions(parameters:token:)")
    public func getAssertions(
        parameters: CTAP2.GetAssertion.Parameters,
        pinToken: CTAP2.Token?
    ) async -> CTAP2.GetAssertion.Sequence {
        await getAssertions(parameters: parameters, token: pinToken)
    }

    @available(*, deprecated, renamed: "config(token:)")
    public func config(
        pinToken: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.Config {
        try await config(token: pinToken)
    }

    @available(*, deprecated, renamed: "credentialManagement(token:)")
    public func credentialManagement(
        pinToken: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.CredentialManagement {
        try await credentialManagement(token: pinToken)
    }

    @available(*, deprecated, renamed: "bioEnrollment(token:)")
    public func bioEnrollment(
        pinToken: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        try await bioEnrollment(token: pinToken)
    }

    @available(*, deprecated, renamed: "putBlob(key:data:token:)")
    public func putBlob(
        key: Data,
        data: Data,
        pinToken: CTAP2.Token
    ) async throws(CTAP2.SessionError) {
        try await putBlob(key: key, data: data, token: pinToken)
    }

    @available(*, deprecated, renamed: "deleteBlob(key:token:)")
    public func deleteBlob(
        key: Data,
        pinToken: CTAP2.Token
    ) async throws(CTAP2.SessionError) {
        try await deleteBlob(key: key, token: pinToken)
    }
}
