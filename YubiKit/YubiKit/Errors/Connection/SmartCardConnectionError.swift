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

/// Unified SmartCard connection errors for all connection types (NFC, Lightning, USB).
///
/// These errors represent failures at the transport layer - before any application-level
/// communication begins. They cover device discovery, connection establishment, and
/// low-level data transmission issues.
public enum SmartCardConnectionError: Error, Sendable {
    /// Connection type is not supported on this device.
    case unsupported

    /// Connection to the device was lost.
    case connectionLost

    /// There is already an active connection.
    case busy

    /// No YubiKey devices found or available.
    case noDevicesFound

    /// Connection operation was cancelled.
    case cancelled

    /// Connection was cancelled by the user.
    case cancelledByUser

    /// Failed to set up the connection.
    case setupFailed(String?, Error? = nil)

    /// Failed to transmit data.
    case transmitFailed(String?, Error? = nil)

    /// Provided data is malformed.
    case malformedData(String? = nil)

    /// Failed to poll for devices.
    case pollingFailed(String? = nil)
}

// MARK: - Internal methods to flatten the error
extension SmartCardConnectionError {
    static func setupFailed(_ message: String? = nil, flatten error: Error?) -> Self {
        if let connectionError = error as? SmartCardConnectionError { return connectionError }
        return .setupFailed(message, error)
    }

    static func transmitFailed(_ message: String? = nil, flatten error: Error?) -> Self {
        if let connectionError = error as? SmartCardConnectionError { return connectionError }
        return .transmitFailed(message, error)
    }
}
