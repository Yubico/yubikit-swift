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

/// Base protocol defining a physical connection to a YubiKey.
///
/// This is the base protocol for all YubiKey connections. Specific connection types
/// like ``SmartCardConnection`` and ``FIDOConnection`` extend this protocol
public protocol Connection: Sendable {

    /// Close the current connection.
    ///
    /// This closes the connection sending the optional error to the ``connectionDidClose()`` method.
    func close(error: Error?) async

    /// Wait for the connection to close.
    ///
    /// This method will wait until the connection closes. If the connection was closed due to an error said
    /// error will be returned.
    func connectionDidClose() async -> Error?
}

/// Connection Errors.
public enum ConnectionError: Error, Sendable {
    /// There is an active connection.
    case busy
    /// No current connection.
    case noConnection
    /// Unexpected result returned from YubiKey.
    case unexpectedResult
    /// Awaiting call to connect() was cancelled.
    case cancelled
    /// Awaiting call to connect() was dismissed by the user.
    case cancelledByUser
}
