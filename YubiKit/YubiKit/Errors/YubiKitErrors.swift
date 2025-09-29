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

import CommonCrypto
import Foundation

/// Source location information for debugging and error reporting.
public struct SourceLocation: Sendable {
    /// The source file where the error occurred.
    public let file: String
    /// The function where the error occurred.
    public let function: String
    /// The line number where the error occurred.
    public let line: Int
    /// The column number where the error occurred.
    public let column: Int
}

// MARK: - Session Error Protocol

/// Common protocol for all session error types.
/// Enforces common error cases that all sessions must handle.
public protocol SessionError: Error, Sendable {
    /// Connection error occurred during communication with the YubiKey.
    static func connectionError(
        _ error: SmartCardConnectionError,
        source: SourceLocation
    ) -> Self

    /// Response status error that couldn't be handled specifically by the session.
    static func failedResponse(
        _ responseStatus: ResponseStatus,
        source: SourceLocation
    ) -> Self

    /// SCP-level error occurred during secure channel operations.
    static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self

    /// Encryption or cryptographic operation failed.
    static func encryptionFailed(
        _ message: String,
        error: Error?,
        source: SourceLocation
    ) -> Self

    /// Failed to parse data received from the YubiKey.
    static func responseParseError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Failed to process or encode data for use with the YubiKey.
    static func dataProcessingError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Feature is not supported on this YubiKey.
    static func featureNotSupported(
        source: SourceLocation
    ) -> Self

    /// The application is not available on this YubiKey.
    static func missingApplication(
        source: SourceLocation
    ) -> Self

    /// Invalid argument provided to a method.
    static func illegalArgument(
        _ message: String,
        source: SourceLocation
    ) -> Self
}

// MARK: - Transport Errors

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
    case setupFailed(String? = nil, Error? = nil)

    /// Failed to transmit data.
    case transmitFailed(String? = nil, Error? = nil)

    /// Provided data is malformed.
    case malformedData(String? = nil)

    /// Failed to poll for devices.
    case pollingFailed(String? = nil)
}

// MARK: - Utility Errors

/// Errors related to encryption operations.
public enum EncryptionError: Error, Sendable {
    /// CommonCrypto cryptor operation failed.
    case cryptorError(CCCryptorStatus)

    /// Required data is missing for the cryptographic operation.
    case missingData

    /// The requested cryptographic algorithm is not supported.
    case unsupportedAlgorithm
}
