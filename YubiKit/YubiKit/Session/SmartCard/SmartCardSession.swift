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

/// A protocol for sessions that communicate with YubiKey applications using SmartCard connections.
///
/// SmartCardSession extends ``Session`` to provide session creation with SmartCard connections,
/// supporting communication over NFC, Lightning, and USB interfaces with optional secure channel encryption.
public protocol SmartCardSession: Session {
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
    ) async throws -> Self
}
