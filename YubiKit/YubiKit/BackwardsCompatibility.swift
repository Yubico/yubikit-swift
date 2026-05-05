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

/// This file contains deprecated API for backwards compatibility.
/// These APIs will be removed in the next major version.

// MARK: - EC.PublicKey Deprecated API

extension EC.PublicKey {

    // Legacy names (pre-x963Representation era)

    /// Initialize a public key from SEC1 uncompressed EC point format (0x04 || X || Y).
    /// - Parameters:
    ///   - uncompressedPoint: Data in SEC1 format.
    ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
    /// - Returns: PublicKey if valid, otherwise nil.
    @available(*, deprecated, renamed: "init(x963:curve:)")
    public init?(uncompressedPoint: Data, curve: EC.Curve) {
        self.init(x963: uncompressedPoint, curve: curve)
    }

    /// SEC1 uncompressed EC point representation (0x04 || X || Y).
    @available(*, deprecated, renamed: "x963")
    public var uncompressedPoint: Data { x963 }

    // Deprecated in favor of shorter `x963`

    /// Initialize a public key from X9.63 format (0x04 || X || Y).
    /// - Parameters:
    ///   - x963Representation: The X9.63 encoded public key data.
    ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
    /// - Returns: PublicKey if valid, otherwise nil.
    @available(*, deprecated, renamed: "init(x963:curve:)")
    public init?(x963Representation: Data, curve: EC.Curve) {
        self.init(x963: x963Representation, curve: curve)
    }

    /// X9.63 representation (0x04 || X || Y).
    @available(*, deprecated, renamed: "x963")
    public var x963Representation: Data { x963 }
}

// MARK: - EC.PrivateKey Deprecated API

extension EC.PrivateKey {

    // Legacy names (pre-x963Representation era)

    /// Initialize a private key from 0x04 || X || Y || K
    /// - Parameters:
    ///   - uncompressedRepresentation: uncompressedPoint + K
    ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
    /// - Returns: PrivateKey if valid, otherwise nil.
    @available(*, deprecated, renamed: "init(x963:curve:)")
    public init?(uncompressedRepresentation: Data, curve: EC.Curve) {
        self.init(x963: uncompressedRepresentation, curve: curve)
    }

    /// Uncompressed representation of private key as 0x04 || X || Y || K.
    @available(*, deprecated, renamed: "x963")
    public var uncompressedRepresentation: Data { x963 }

    // Deprecated in favor of shorter `x963`

    /// Initialize a private key from X9.63 format (0x04 || X || Y || K).
    /// - Parameters:
    ///   - x963Representation: The X9.63 encoded private key data.
    ///   - curve: The elliptic curve type (secp256r1 or secp384r1).
    /// - Returns: PrivateKey if valid, otherwise nil.
    @available(*, deprecated, renamed: "init(x963:curve:)")
    public init?(x963Representation: Data, curve: EC.Curve) {
        self.init(x963: x963Representation, curve: curve)
    }

    /// X9.63 representation of private key as 0x04 || X || Y || K.
    @available(*, deprecated, renamed: "x963")
    public var x963Representation: Data { x963 }
}

// MARK: - Response Deprecated API

extension Response {

    /// Convenience property to access sw1 directly
    @available(*, deprecated, message: "Use responseStatus.sw1 instead")
    public var sw1: UInt8 {
        responseStatus.sw1
    }

    /// Convenience property to access sw2 directly
    @available(*, deprecated, message: "Use responseStatus.sw2 instead")
    public var sw2: UInt8 {
        responseStatus.sw2
    }
}

@available(*, deprecated, renamed: "Response.Status")
public typealias ResponseStatus = Response.Status

extension Response.Status {
    @available(*, deprecated, renamed: "Response.Status.Code")
    public typealias StatusCode = Code
}

// MARK: - Management Deprecated API

@available(*, deprecated, renamed: "Management.Session")
public typealias ManagementSession = Management.Session

@available(*, deprecated, renamed: "Management.Feature")
public typealias ManagementFeature = Management.Feature

// MARK: - PIVSessionError Deprecated API

extension PIVSessionError {

    /// Gzip compression/decompression failed.
    @available(*, deprecated, renamed: "compression")
    public static func gzip(_ error: Error, source: SourceLocation) -> PIVSessionError {
        .compression(error, source: source)
    }
}

// MARK: - WebAuthn.PublicKeyCredential Deprecated Namespace

extension WebAuthn {
    /// Deprecated host for the legacy nested entity types. Use
    /// ``WebAuthn/User``, ``WebAuthn/RelyingParty``, and
    /// ``WebAuthn/CredentialDescriptor`` directly.
    public enum PublicKeyCredential {}
}

extension WebAuthn.PublicKeyCredential {
    @available(*, deprecated, renamed: "WebAuthn.User")
    public typealias UserEntity = WebAuthn.User

    @available(*, deprecated, renamed: "WebAuthn.CredentialDescriptor")
    public typealias Descriptor = WebAuthn.CredentialDescriptor

    @available(*, deprecated, renamed: "WebAuthn.RelyingParty")
    public typealias RPEntity = WebAuthn.RelyingParty
}

// MARK: - CTAP2.MakeCredential.Response Deprecated API

extension CTAP2.MakeCredential.Response {

    /// Attestation statement format identifier.
    @available(*, deprecated, renamed: "attestationObject.format")
    public var format: String { attestationObject.format }

    /// Parsed attestation statement.
    @available(*, deprecated, renamed: "attestationObject.statement")
    public var attestationStatement: WebAuthn.AttestationStatement { attestationObject.statement }
}

// MARK: - CTAP2.ClientPin Deprecated Token Type

extension CTAP2.ClientPin {
    @available(*, deprecated, renamed: "CTAP2.Token")
    public typealias Token = CTAP2.Token
}

// MARK: - CTAP2.MakeCredential.Parameters Deprecated Options

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
        rp: WebAuthn.RelyingParty,
        user: WebAuthn.User,
        pubKeyCredParams: [COSE.Algorithm],
        excludeList: [WebAuthn.CredentialDescriptor]? = nil,
        extensions: [CTAP2.Extension.MakeCredential.Input] = [],
        options: Options?,
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

// MARK: - CTAP2.GetAssertion.Parameters Deprecated Options

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
        allowList: [WebAuthn.CredentialDescriptor]? = nil,
        extensions: [CTAP2.Extension.GetAssertion.Input] = [],
        options: Options?
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

// MARK: - CTAP2.Session Deprecated Methods

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
