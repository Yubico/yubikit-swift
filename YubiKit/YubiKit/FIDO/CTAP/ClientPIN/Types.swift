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

// MARK: - PinUVAuthToken Protocol

extension CTAP2.ClientPin {
    /// Protocol for tokens that can authenticate CTAP2 management operations.
    internal protocol PinUVAuthToken: Sendable {
        var protocolVersion: CTAP2.ClientPin.ProtocolVersion { get }
        func authenticate(message: Data) -> Data
        func deriveKey(info: String) -> Data
    }
}

// MARK: - ClientPin Types

extension CTAP2.ClientPin {
    /// PIN/UV Auth Protocol version.
    public enum ProtocolVersion: Int, Sendable, CBOR.Encodable {
        /// Protocol version 1 (CTAP 2.0).
        case v1 = 1

        /// Protocol version 2 (CTAP 2.1+).
        case v2 = 2
    }

    /// Method for PIN/UV user verification.
    public enum Method: Sendable {
        /// Verify using a PIN.
        case pin(String)
        /// Verify using built-in user verification (e.g., fingerprint).
        case uv
    }

    /// A PIN auth token for authenticating CTAP2 operations.
    ///
    /// Obtain via ``CTAP2/Session/getPinToken(_:permissions:rpId:protocol:)``.
    public struct PinToken: Sendable {
        private let token: Data
        public let protocolVersion: ProtocolVersion

        internal init(token: Data, protocolVersion: ProtocolVersion) {
            self.token = token
            self.protocolVersion = protocolVersion
        }

        func authenticate(message: Data) -> Data {
            protocolVersion.authenticate(key: token, message: message)
        }

        internal func deriveKey(info: String) -> Data {
            Crypto.KDF.hkdf(token, salt: Data(count: 32), info: info, outputLength: 16)
        }
    }

    /// A UV auth token obtained via built-in user verification (biometric).
    ///
    /// Obtain via ``CTAP2/Session/getUVToken(permissions:rpId:protocol:)``.
    public struct UVToken: Sendable {
        private let token: Data
        public let protocolVersion: ProtocolVersion

        internal init(token: Data, protocolVersion: ProtocolVersion) {
            self.token = token
            self.protocolVersion = protocolVersion
        }

        func authenticate(message: Data) -> Data {
            protocolVersion.authenticate(key: token, message: message)
        }

        internal func deriveKey(info: String) -> Data {
            Crypto.KDF.hkdf(token, salt: Data(count: 32), info: info, outputLength: 16)
        }
    }

    // MARK: - Backwards Compatibility

    /// A PIN/UV auth token (deprecated, use ``PinToken`` or ``UVToken``).
    @available(*, deprecated, message: "Use PinToken or UVToken directly")
    public struct Token: Sendable {
        internal enum TokenType {
            case pin(PinToken)
            case uv(UVToken)
        }

        internal let type: TokenType

        public var protocolVersion: ProtocolVersion {
            switch type {
            case .pin(let token): return token.protocolVersion
            case .uv(let token): return token.protocolVersion
            }
        }

        internal init(pinToken: PinToken) {
            self.type = .pin(pinToken)
        }

        internal init(uvToken: UVToken) {
            self.type = .uv(uvToken)
        }

        func authenticate(message: Data) -> Data {
            switch type {
            case .pin(let token): return token.authenticate(message: message)
            case .uv(let token): return token.authenticate(message: message)
            }
        }

        func deriveKey(info: String) -> Data {
            switch type {
            case .pin(let token): return token.deriveKey(info: info)
            case .uv(let token): return token.deriveKey(info: info)
            }
        }
    }
}

// MARK: - PinUVAuthToken Conformances

extension CTAP2.ClientPin.PinToken: CTAP2.ClientPin.PinUVAuthToken {}
extension CTAP2.ClientPin.UVToken: CTAP2.ClientPin.PinUVAuthToken {}

@available(*, deprecated, message: "Use PinToken or UVToken directly")
extension CTAP2.ClientPin.Token: CTAP2.ClientPin.PinUVAuthToken {}
