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

extension WebAuthn {
    /// Authenticator transport identifiers.
    ///
    /// These indicate the transports an authenticator supports for communication.
    ///
    /// - SeeAlso: [WebAuthn AuthenticatorTransport](https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport)
    public enum Transport: Sendable, Hashable {
        /// USB transport.
        case usb

        /// NFC (Near Field Communication) transport.
        case nfc

        /// Bluetooth Low Energy transport.
        case ble

        /// Smart card transport.
        case smartCard

        /// Hybrid transport (e.g., cross-device authentication via QR code).
        case hybrid

        /// Internal/platform authenticator transport.
        case `internal`

        /// Unknown or future transport type.
        case unknown(String)

        /// The string representation of the transport.
        public var rawValue: String {
            switch self {
            case .usb: return "usb"
            case .nfc: return "nfc"
            case .ble: return "ble"
            case .smartCard: return "smart-card"
            case .hybrid: return "hybrid"
            case .internal: return "internal"
            case .unknown(let value): return value
            }
        }

        /// Initialize from a string value.
        public init(rawValue: String) {
            switch rawValue {
            case "usb": self = .usb
            case "nfc": self = .nfc
            case "ble": self = .ble
            case "smart-card": self = .smartCard
            case "hybrid": self = .hybrid
            case "internal": self = .internal
            default: self = .unknown(rawValue)
            }
        }
    }
}

// MARK: - CBOR Conformance

extension WebAuthn.Transport: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let string: String = cbor.cborDecoded() else {
            return nil
        }
        self.init(rawValue: string)
    }
}

extension WebAuthn.Transport: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .textString(rawValue)
    }
}
