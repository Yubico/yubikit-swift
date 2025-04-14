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
public protocol Session: Sendable {
    
    /// Returns a new session using the supplied connection.
    static func session(withConnection connection: Connection, scpKeyParams: SCPKeyParams?) async throws -> Self
    
    /// Determine wether the Session supports the specific feature.
    func supports(_ feature: SessionFeature) -> Bool
}

public protocol SessionFeature {
    func isSupported(by version: Version) -> Bool
}

public enum SessionError: Error {
    case notSupported
    case activeSession
    case missingApplication
    case unexpectedResult
    case unexpectedStatusCode
    case unexpectedResponse
    case illegalArgument
    case invalidPin(Int)
}

extension SessionError: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.notSupported, .notSupported):
            return true
        case (.activeSession, .activeSession):
            return true
        case (.missingApplication, .missingApplication):
            return true
        case (.unexpectedResult, .unexpectedResult):
            return true
        case (.unexpectedStatusCode, .unexpectedStatusCode):
            return true
        case (.unexpectedResponse, .unexpectedResponse):
            return true
        case (.illegalArgument, .illegalArgument):
            return true
        case (.invalidPin(_), .invalidPin(_)):
            return true
        default:
            return false
        }
    }
}
