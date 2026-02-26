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

// MARK: - Session Config Accessor

extension CTAP2.Session {
    /// Returns authenticatorConfig operations bound to a PIN/UV auth token.
    ///
    /// ```swift
    /// let token = try await session.getPinUVToken(
    ///     using: .pin("123456"),
    ///     permissions: [.authenticatorConfig]
    /// )
    /// let config = try await session.config(token: token)
    /// try await config.toggleAlwaysUV()
    /// try await config.enableEnterpriseAttestation()
    /// ```
    ///
    /// - Parameter token: PIN/UV auth token with `authenticatorConfig` permission.
    /// - Returns: Config operations bound to the token.
    /// - Throws: `CTAP2.SessionError.featureNotSupported` if authenticatorConfig is not supported.
    /// - SeeAlso: [CTAP2 authenticatorConfig](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorConfig)
    public func config(
        token: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.Config {
        guard try await cachedInfo.options.authenticatorConfig else {
            throw .featureNotSupported(source: .here())
        }
        return CTAP2.Config(session: self, token: token)
    }
}

// MARK: - Config

extension CTAP2 {
    /// AuthenticatorConfig operations bound to a PIN/UV auth token.
    ///
    /// - SeeAlso: [CTAP2 authenticatorConfig](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorConfig)
    public struct Config: Sendable {
        private let session: CTAP2.Session
        private let token: CTAP2.Token

        fileprivate init(session: CTAP2.Session, token: CTAP2.Token) {
            self.session = session
            self.token = token
        }

        /// Checks if the authenticator supports authenticatorConfig.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports authenticatorConfig.
        public static func isSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.options.authenticatorConfig
        }

        /// Enables enterprise attestation. If already enabled, this command is ignored.
        ///
        /// - SeeAlso: [Enable Enterprise Attestation](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#enable-enterprise-attestation)
        public func enableEnterpriseAttestation() async throws(CTAP2.SessionError) {
            try await execute(subcommand: .enableEnterpriseAttestation)
        }

        /// Toggles the alwaysUV setting.
        ///
        /// When enabled, the authenticator always requires user verification for assertions.
        ///
        /// - SeeAlso: [Toggle Always Require User Verification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#toggle-alwaysUv)
        public func toggleAlwaysUV() async throws(CTAP2.SessionError) {
            try await execute(subcommand: .toggleAlwaysUV)
        }

        /// Sets the minimum PIN length and related configuration.
        ///
        /// - Parameters:
        ///   - newMinPINLength: The minimum PIN length to allow. Pass `nil` to keep current.
        ///   - rpIDs: RP IDs allowed to query minimum PIN length via extension.
        ///   - forceChangePin: Enforce PIN change before next use.
        /// - SeeAlso: [Setting a Minimum PIN Length](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#setMinPINLength)
        public func setMinPINLength(
            newMinPINLength: UInt? = nil,
            rpIDs: [String]? = nil,
            forceChangePin: Bool = false
        ) async throws(CTAP2.SessionError) {
            var params: [UInt8: CBOR.Value] = [:]
            if let length = newMinPINLength {
                params[Parameter.newMinPINLength.rawValue] = length.cbor()
            }
            if let rpIDs {
                params[Parameter.minPINLengthRPIDs.rawValue] = rpIDs.cbor()
            }
            if forceChangePin {
                params[Parameter.forceChangePin.rawValue] = true.cbor()
            }

            try await execute(subcommand: .setMinPINLength, params: params)
        }

        // MARK: - Internal

        private func execute(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) {
            let message = authMessage(subcommand: subcommand, params: params)
            let pinUVAuthParam = token.authenticate(message: message)

            let parameters = RequestParameters(
                subCommand: subcommand,
                subCommandParams: params,
                pinUVAuthProtocol: token.protocolVersion,
                pinUVAuthParam: pinUVAuthParam
            )

            try await session.interface.send(
                command: .config,
                payload: parameters
            ).value
        }

        // Format: 0xFF * 32 || 0x0D || subCommand || CBOR(params)
        private func authMessage(subcommand: Subcommand, params: [UInt8: CBOR.Value]?) -> Data {
            var message = Data(repeating: 0xFF, count: 32)
            message.append(CTAP2.Command.config.rawValue)
            message.append(subcommand.rawValue)
            if let params {
                let cborParams = params.cbor()
                message.append(cborParams.encode())
            }
            return message
        }
    }
}

// MARK: - Internal Types

extension CTAP2.Config {
    /// Subcommands for the authenticatorConfig command.
    ///
    /// Authenticators report supported subcommands in ``CTAP2/GetInfo/Response/authenticatorConfigCommands``.
    public enum Subcommand: RawRepresentable, Sendable, Equatable {
        /// Enable enterprise attestation.
        case enableEnterpriseAttestation
        /// Toggle the alwaysUV setting.
        case toggleAlwaysUV
        /// Set minimum PIN length.
        case setMinPINLength
        /// Vendor-specific prototype command.
        case vendorPrototype
        /// Unknown or future subcommand.
        case other(UInt8)

        /// The CTAP2 subcommand byte value.
        public var rawValue: UInt8 {
            switch self {
            case .enableEnterpriseAttestation: return 0x01
            case .toggleAlwaysUV: return 0x02
            case .setMinPINLength: return 0x03
            case .vendorPrototype: return 0xFF
            case .other(let value): return value
            }
        }

        /// Creates a subcommand from its CTAP2 byte value.
        public init(rawValue: UInt8) {
            switch rawValue {
            case 0x01: self = .enableEnterpriseAttestation
            case 0x02: self = .toggleAlwaysUV
            case 0x03: self = .setMinPINLength
            case 0xFF: self = .vendorPrototype
            default: self = .other(rawValue)
            }
        }
    }

    fileprivate enum Parameter: UInt8, Sendable {
        case newMinPINLength = 0x01
        case minPINLengthRPIDs = 0x02
        case forceChangePin = 0x03
    }

    fileprivate struct RequestParameters: Sendable, CBOR.Encodable {
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
}
