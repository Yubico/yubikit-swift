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

/// A protocol defining a session with a specific application on the YubiKey.
///
/// The Session uses a ``Connection`` to handle communication with the YubiKey. Using a session is the preferred way
/// of communicating with the different applications on the YubiKey.
///
/// The protocol is implemented by ``OATHSession`` and ``ManagementSession``.
public protocol Session: AnyObject {
    
    /// Returns a new session using the supplied connection.
    static func session(withConnection connection: Connection) async throws -> Self
    
    /// Determine wether the Session supports the specific feature.
    func supports(_ feature: SessionFeature) -> Bool

    /// End the session. This will remove its internal connection and discard any state saved by the session.
    /// The connection to the YubiKey will be kept open.
    func end() async
}

internal protocol InternalSession {
    func connection() async -> Connection?
    func setConnection(_ connection: Connection?) async
}

extension InternalSession {
    func internalConnection() async -> InternalConnection? {
        let connection = await connection()
        return connection as? InternalConnection
    }
}

public protocol SessionFeature {
    func isSupported(by version: Version) -> Bool
}

public enum SessionError: Error {
    case noConnection
    case notSupported
    case activeSession
    case missingApplication
    case unexpectedStatusCode
    case illegalArgument
    case invalidPin(Int)
}
