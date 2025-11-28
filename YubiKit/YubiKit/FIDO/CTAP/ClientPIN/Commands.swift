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

// MARK: - Command Protocol

extension CTAP2.ClientPIN {
    /// Protocol for type-safe ClientPIN subcommand parameters.
    ///
    /// Each subcommand has a specific parameter type that conforms to this protocol,
    /// ensuring only valid parameter combinations can be constructed.
    protocol Command: CBOR.Encodable, Sendable {
        /// The response type returned by this subcommand.
        associatedtype Response: Sendable

        /// The subcommand code.
        static var commandCode: UInt8 { get }
    }
}

// MARK: - Command Namespaces

extension CTAP2.ClientPIN {

    /// Namespace for the getPinRetries subcommand (0x01).
    enum GetRetries {
        static let commandCode: UInt8 = 0x01
    }

    /// Namespace for the getKeyAgreement subcommand (0x02).
    enum GetKeyAgreement {
        static let commandCode: UInt8 = 0x02
    }

    /// Namespace for the setPIN subcommand (0x03).
    enum SetPIN {
        static let commandCode: UInt8 = 0x03
    }

    /// Namespace for the changePIN subcommand (0x04).
    enum ChangePIN {
        static let commandCode: UInt8 = 0x04
    }

    /// Namespace for the getPinToken subcommand (0x05, legacy CTAP 2.0).
    enum GetToken {
        static let commandCode: UInt8 = 0x05
    }

    /// Namespace for the getUVRetries subcommand (0x07).
    enum GetUvRetries {
        static let commandCode: UInt8 = 0x07
    }

    /// Namespace for the getPinUvAuthTokenUsingPinWithPermissions subcommand (0x09).
    enum GetTokenWithPermissions {
        static let commandCode: UInt8 = 0x09
    }
}
