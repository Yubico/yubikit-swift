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

// MARK: - Session CredentialManagement Accessor

extension CTAP2.Session {
    /// Returns credential management operations bound to a PIN/UV auth token.
    ///
    /// ```swift
    /// let token = try await session.getPinUVToken(
    ///     using: .pin("123456"),
    ///     permissions: [.credentialManagement]
    /// )
    /// let credMgmt = try await session.credentialManagement(token: token)
    /// let metadata = try await credMgmt.getMetadata()
    /// let rps = try await credMgmt.rps.enumerate()
    /// ```
    ///
    /// - Parameter token: PIN/UV auth token with `credentialManagement` permission.
    /// - Returns: CredentialManagement operations bound to the token.
    /// - Throws: `CTAP2.SessionError.featureNotSupported` if credential management is not supported.
    /// - SeeAlso: [CTAP2 authenticatorCredentialManagement](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorCredentialManagement)
    public func credentialManagement(
        token: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.CredentialManagement {
        guard try await CTAP2.CredentialManagement.isSupported(by: self) else {
            throw .featureNotSupported(source: .here())
        }
        return CTAP2.CredentialManagement(session: self, token: token)
    }
}

// MARK: - CredentialManagement

extension CTAP2 {
    /// Credential management operations bound to a PIN/UV auth token.
    ///
    /// Allows managing discoverable (resident) credentials stored on the authenticator.
    ///
    /// - SeeAlso: [CTAP2 authenticatorCredentialManagement](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorCredentialManagement)
    public struct CredentialManagement: Sendable {
        private let session: CTAP2.Session
        private let token: CTAP2.Token

        fileprivate init(session: CTAP2.Session, token: CTAP2.Token) {
            self.session = session
            self.token = token
        }

        // MARK: - Feature Detection

        /// Checks if the authenticator supports credential management.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports credential management.
        public static func isSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            // Check for CTAP 2.1+ credMgmt or FIDO_2_1_PRE credentialMgmtPreview
            return info.options.credentialManagement
                || (info.versions.contains(.fido2_1Pre) && info.options.credentialMgmtPreview)
        }

        /// Checks if the authenticator supports updating user information.
        ///
        /// Update user information is only available with full CTAP 2.1+ credential management,
        /// not with the FIDO_2_1_PRE prototype command.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports updating user information.
        public static func isUpdateSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.options.credentialManagement
        }

        /// Checks if the authenticator supports read-only credential management with a persistent token.
        ///
        /// When supported, read-only operations (enumerate RPs, enumerate credentials, get metadata)
        /// can use a persistent PIN/UV auth token without requiring re-authentication each time.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports read-only credential management.
        public static func isReadOnlySupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.options.perCredMgmtRO
        }

        // MARK: - Operations

        /// Gets metadata about stored credentials.
        ///
        /// Returns the total number of discoverable credentials and the maximum
        /// number of additional credentials that can be stored.
        ///
        /// - Returns: Metadata containing credential counts.
        /// - SeeAlso: [Getting Credentials Metadata](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#getCredsMetadata)
        public func getMetadata() async throws(CTAP2.SessionError) -> Metadata {
            try await execute(subcommand: .getCredsMetadata)
        }

        /// Deletes a credential from the authenticator.
        ///
        /// - Parameter credentialId: The credential descriptor identifying the credential to delete.
        /// - SeeAlso: [DeleteCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#deleteCredential)
        public func deleteCredential(
            _ credentialId: WebAuthn.CredentialDescriptor
        ) async throws(CTAP2.SessionError) {
            let params: [UInt8: CBOR.Value] = [
                Parameter.credentialId.rawValue: credentialId.cbor()
            ]

            try await execute(subcommand: .deleteCredential, params: params) as Void
        }

        /// Updates user information for a credential.
        ///
        /// This operation is only available on authenticators with full CTAP 2.1+
        /// credential management support (not FIDO_2_1_PRE prototype).
        ///
        /// - Parameters:
        ///   - credentialId: The credential descriptor identifying the credential to update.
        ///   - user: The updated user entity information.
        /// - Throws: `CTAP2.SessionError.featureNotSupported` if update is not supported.
        /// - SeeAlso: [Updating user information](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#updateUserInformation)
        public func updateUserInformation(
            credentialId: WebAuthn.CredentialDescriptor,
            user: WebAuthn.User
        ) async throws(CTAP2.SessionError) {
            guard try await Self.isUpdateSupported(by: session) else {
                throw .featureNotSupported(source: .here())
            }

            let params: [UInt8: CBOR.Value] = [
                Parameter.credentialId.rawValue: credentialId.cbor(),
                Parameter.user.rawValue: user.cbor(),
            ]

            try await execute(subcommand: .updateUserInformation, params: params) as Void
        }

        // MARK: - Internal

        func execute<R: CBOR.Decodable & Sendable>(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) -> R {
            let parameters = authParameters(subcommand: subcommand, params: params)
            let command = try await commandCode()
            return try await session.interface.send(command: command, payload: parameters).value
        }

        func execute(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) {
            let parameters = authParameters(subcommand: subcommand, params: params)
            let command = try await commandCode()
            try await session.interface.send(command: command, payload: parameters).value
        }

        func executeNoAuth<R: CBOR.Decodable & Sendable>(
            subcommand: Subcommand
        ) async throws(CTAP2.SessionError) -> R {
            let command = try await commandCode()
            return try await session.interface.send(
                command: command,
                payload: RequestParametersNoAuth(subCommand: subcommand)
            ).value
        }

        private func authParameters(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]?
        ) -> RequestParameters {
            // Auth message format: subCommand || CBOR(params)
            var message = Data([subcommand.rawValue])
            if let params {
                message.append(params.cbor().encode())
            }
            return RequestParameters(
                subCommand: subcommand,
                subCommandParams: params,
                pinUVAuthProtocol: token.protocolVersion,
                pinUVAuthParam: token.authenticate(message: message)
            )
        }

        private func commandCode() async throws(CTAP2.SessionError) -> CTAP2.Command {
            let info = try await session.cachedInfo
            return info.options.credentialManagement
                ? .credentialManagement
                : .credentialManagementPreview
        }
    }
}

// MARK: - Internal Types

extension CTAP2.CredentialManagement {
    enum Subcommand: UInt8, Sendable {
        case getCredsMetadata = 0x01
        case enumerateRPsBegin = 0x02
        case enumerateRPsGetNextRP = 0x03
        case enumerateCredentialsBegin = 0x04
        case enumerateCredentialsGetNextCredential = 0x05
        case deleteCredential = 0x06
        case updateUserInformation = 0x07
    }

    enum Parameter: UInt8, Sendable {
        case rpIdHash = 0x01
        case credentialId = 0x02
        case user = 0x03
    }

    struct RequestParameters: Sendable, CBOR.Encodable {
        let subCommand: Subcommand
        let subCommandParams: [UInt8: CBOR.Value]?
        let pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion
        let pinUVAuthParam: Data

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [:]
            map[.int(0x01)] = .int(Int(subCommand.rawValue))
            if let params = subCommandParams, !params.isEmpty {
                var paramsMap: [CBOR.Value: CBOR.Value] = [:]
                for (key, value) in params {
                    paramsMap[.int(Int(key))] = value
                }
                map[.int(0x02)] = .map(paramsMap)
            }
            map[.int(0x03)] = pinUVAuthProtocol.cbor()
            map[.int(0x04)] = pinUVAuthParam.cbor()
            return .map(map)
        }
    }

    struct RequestParametersNoAuth: Sendable, CBOR.Encodable {
        let subCommand: Subcommand

        func cbor() -> CBOR.Value {
            let map: [CBOR.Value: CBOR.Value] = [.int(0x01): .int(Int(subCommand.rawValue))]
            return .map(map)
        }
    }
}
