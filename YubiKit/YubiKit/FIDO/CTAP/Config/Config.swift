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
    /// let pinToken = try await session.getPinUVToken(
    ///     using: .pin("123456"),
    ///     permissions: [.authenticatorConfig]
    /// )
    /// let config = session.config(pinToken: pinToken)
    /// try await config.toggleAlwaysUV()
    /// try await config.enableEnterpriseAttestation()
    /// ```
    ///
    /// - Parameter pinToken: PIN/UV auth token with `authenticatorConfig` permission.
    /// - Returns: Config operations bound to the token.
    /// - SeeAlso: [CTAP2 authenticatorConfig](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorConfig)
    public func config(pinToken: CTAP2.ClientPin.Token) -> CTAP2.Config {
        CTAP2.Config(session: self, pinToken: pinToken)
    }
}

// MARK: - Config

extension CTAP2 {
    /// AuthenticatorConfig operations bound to a PIN/UV auth token.
    ///
    /// - SeeAlso: [CTAP2 authenticatorConfig](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorConfig)
    public struct Config: Sendable {
        private let session: CTAP2.Session
        private let pinToken: CTAP2.ClientPin.Token

        init(session: CTAP2.Session, pinToken: CTAP2.ClientPin.Token) {
            self.session = session
            self.pinToken = pinToken
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
        ///   - pinComplexityPolicy: Enable PIN complexity enforcement.
        /// - Throws: `CTAP2.SessionError.illegalArgument` if `pinComplexityPolicy` is unsupported.
        /// - SeeAlso: [Setting a Minimum PIN Length](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#setMinPINLength)
        public func setMinPINLength(
            newMinPINLength: UInt? = nil,
            rpIDs: [String]? = nil,
            forceChangePin: Bool = false,
            pinComplexityPolicy: Bool = false
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
            if pinComplexityPolicy {
                let info = try await session.getInfo()
                guard info.pinComplexityPolicy != nil else {
                    throw .illegalArgument(
                        "Authenticator does not support PIN complexity policy",
                        source: .here()
                    )
                }
                params[Parameter.pinComplexityPolicy.rawValue] = true.cbor()
            }

            try await execute(subcommand: .setMinPINLength, params: params)
        }

        // MARK: - Internal

        private func execute(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) {
            let message = authMessage(subcommand: subcommand, params: params)
            let pinUVAuthParam = pinToken.authenticate(message: message)

            let parameters = RequestParameters(
                subCommand: subcommand,
                subCommandParams: params,
                pinUVAuthProtocol: pinToken.protocolVersion,
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
    fileprivate enum Subcommand: UInt8, Sendable {
        case enableEnterpriseAttestation = 0x01
        case toggleAlwaysUV = 0x02
        case setMinPINLength = 0x03
        case vendorPrototype = 0xFF
    }

    fileprivate enum Parameter: UInt8, Sendable {
        case newMinPINLength = 0x01
        case minPINLengthRPIDs = 0x02
        case forceChangePin = 0x03
        case pinComplexityPolicy = 0x04
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
