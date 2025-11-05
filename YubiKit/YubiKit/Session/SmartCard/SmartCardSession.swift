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

/// Identifies a YubiKey application that can be selected on a SmartCard connection.
public enum Application: Sendable {
    case oath
    case management
    case piv
    case securityDomain
    case fido2
}

/// A protocol for sessions that communicate with YubiKey applications using SmartCard connections.
///
/// SmartCardSession extends ``Session`` to provide session creation with SmartCard connections,
/// supporting communication over NFC, Lightning, and USB interfaces with optional secure channel encryption.
public protocol SmartCardSession: Session {

    associatedtype Error: SmartCardSessionError

    static var application: Application { get }

    var scpState: SCPState? { get }

    var connection: SmartCardConnection { get }

    /// Creates a new session using the supplied connection.
    ///
    /// - Parameters:
    ///   - connection: The SmartCard connection to use for communication.
    ///   - scpKeyParams: Optional SCP key parameters for encrypted communication.
    /// - Returns: A new session instance for the specific application.
    /// - Throws: An error if the session cannot be established.
    static func makeSession(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams?
    ) async throws(Self.Error) -> Self
}

protocol SmartCardSessionInternal: SmartCardSession {
    var interface: SmartCardInterface<Error> { get }
}

extension SmartCardSessionInternal {
    public var scpState: SCPState? {
        interface.scpState
    }

    public var connection: SmartCardConnection {
        interface.connection
    }

    @discardableResult
    func process(apdu: APDU) async throws(Self.Error) -> Data {
        let isOATH = Self.application == .oath

        return try await interface.send(apdu: apdu, insSendRemaining: isOATH ? 0xa5 : 0xc0)
    }
}
