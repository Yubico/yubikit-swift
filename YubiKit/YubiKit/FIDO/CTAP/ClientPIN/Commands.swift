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

extension CTAP2.ClientPin {
    /// Protocol for type-safe ClientPin subcommand parameters.
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

extension CTAP2.ClientPin {

    /// Namespace for the getPinRetries subcommand (0x01).
    public enum GetRetries {}

    /// Namespace for the getKeyAgreement subcommand (0x02).
    public enum GetKeyAgreement {}

    /// Namespace for the setPin subcommand (0x03).
    public enum SetPin {}

    /// Namespace for the changePin subcommand (0x04).
    public enum ChangePin {}

    /// Namespace for the getPinToken subcommand (0x05, legacy CTAP 2.0).
    public enum GetToken {}

    /// Namespace for the getPinUVAuthTokenUsingUVWithPermissions subcommand (0x06).
    public enum GetTokenUsingUV {}

    /// Namespace for the getUVRetries subcommand (0x07).
    public enum GetUVRetries {}

    /// Namespace for the getPinUVAuthTokenUsingPinWithPermissions subcommand (0x09).
    public enum GetTokenWithPermissions {}
}
