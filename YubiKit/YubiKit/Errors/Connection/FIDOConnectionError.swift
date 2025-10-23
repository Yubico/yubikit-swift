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

/// Unified FIDO connection errors for all connection types.
///
/// These errors represent failures at the transport layer for FIDO connections.
/// They cover device discovery, connection establishment, and low-level data transmission issues.
public enum FIDOConnectionError: Error, Sendable {
    /// Connection type is not supported on this device.
    case unsupported

    /// No YubiKey devices found or available.
    case noDevicesFound

    /// Connection to the device was lost.
    case connectionLost

    /// There is already an active connection.
    case busy

    /// Failed to set up the connection.
    case setupFailed(String?, Error? = nil)

    /// Failed to transmit data.
    case transmitFailed(String?, Error? = nil)

    /// Failed to receive data.
    case receiveFailed(String?, Error? = nil)
}

// MARK: - Internal methods to flatten the error
extension FIDOConnectionError {
    static func setupFailed(_ message: String? = nil, flatten error: Error?) -> Self {
        if let connectionError = error as? FIDOConnectionError { return connectionError }
        return .setupFailed(message, error)
    }

    static func transmitFailed(_ message: String? = nil, flatten error: Error?) -> Self {
        if let connectionError = error as? FIDOConnectionError { return connectionError }
        return .transmitFailed(message, error)
    }

    static func receiveFailed(_ message: String? = nil, flatten error: Error?) -> Self {
        if let connectionError = error as? FIDOConnectionError { return connectionError }
        return .receiveFailed(message, error)
    }
}
