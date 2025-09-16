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
/// The Session uses a ``SmartCardConnection`` to handle communication with the YubiKey. Using a session is the preferred way
/// of communicating with the different applications on the YubiKey.
///
/// The protocol is implemented by ``OATHSession`` and ``ManagementSession``.
public protocol Session: Sendable {

    /// The type of features supported by this session.
    associatedtype Feature: SessionFeature

    /// Returns a new session using the supplied connection.
    static func session(
        withConnection connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams?
    ) async throws -> Self

    /// Determine whether the Session supports the specific feature.
    func supports(_ feature: Feature) async -> Bool
}

/// A protocol defining a feature that can be supported by a session.
public protocol SessionFeature: Sendable {
    /// Determines if this feature is supported by the given firmware version.
    /// - Parameter version: The firmware version to check against.
    /// - Returns: true if the feature is supported, false otherwise.
    func isSupported(by version: Version) -> Bool
}

/// Errors that can occur during session operations.
public enum SessionError: Error, Sendable {
    /// The requested operation is not supported.
    case notSupported(_: String?)
    /// There is already an active session.
    case activeSession
    /// The required application is missing or not available.
    case missingApplication
    /// An unexpected result was returned.
    case unexpectedResult
    /// An unexpected status code was returned.
    case unexpectedStatusCode
    /// An unexpected response was received.
    case unexpectedResponse
    /// An illegal argument was provided.
    case illegalArgument(_: String?)

    static var illegalArgument: Self {
        .illegalArgument(nil)
    }

    static var notSupported: Self {
        .notSupported(nil)
    }
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
        default:
            return false
        }
    }
}
