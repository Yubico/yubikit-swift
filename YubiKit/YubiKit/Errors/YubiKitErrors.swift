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

public struct SourceLocation: Sendable {
    public let file: String
    public let function: String
    public let line: Int
    public let column: Int
}

// MARK: - Session Error Protocol

/// Common protocol for all session error types.
/// Enforces common error cases that all sessions must handle.
public protocol SessionError: Error, Sendable {
    /// The underlying connection error occurred during communication with the YubiKey.
    ///
    /// This error is thrown when:
    /// - The connection to the YubiKey is lost
    /// - No YubiKey devices are found
    /// - The connection type is not supported
    /// - Communication with the YubiKey fails at the transport level
    ///
    /// - Parameter error: The specific connection error that occurred
    /// - Returns: A session-specific error wrapping the connection error
    static func connectionError(
        _ error: SmartCardConnectionError,
        source: SourceLocation
    ) -> Self

    /// Response status error that couldn't be handled specifically by the session.
    ///
    /// This error is thrown when:
    /// - The YubiKey returns an unexpected status code
    /// - The operation is not supported by this YubiKey model/version
    /// - Authentication is required but not provided
    /// - The requested operation failed with a generic error
    ///
    /// - Parameter responseStatus: The status code returned by the YubiKey
    /// - Returns: A session-specific error wrapping the response status
    static func failedResponse(
        _ responseStatus: ResponseStatus,
        source: SourceLocation
    ) -> Self

    /// SCP-level error occurred during secure channel operations.
    ///
    /// This error is thrown when:
    /// - SCP authentication fails
    /// - Key derivation or cryptographic operations fail
    /// - SCP channel setup or communication errors occur
    /// - Invalid SCP parameters are provided
    ///
    /// - Parameter error: The specific SCP error that occurred
    /// - Returns: A session-specific error wrapping the SCP error
    static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self

    /// Encryption or cryptographic operation failed.
    ///
    /// This error is thrown when:
    /// - Key generation or derivation fails
    /// - Encryption or decryption operations fail
    /// - MAC verification fails
    /// - Cryptographic algorithm operations fail
    /// - Digital signature operations fail
    ///
    /// - Parameters:
    ///   - message: A descriptive message about what operation failed
    ///   - error: The underlying error
    /// - Returns: A session-specific error describing the encryption failure
    static func encryptionFailed(
        _ message: String,
        error: Error?,
        source: SourceLocation
    ) -> Self

    /// Failed to parse data received from the YubiKey.
    ///
    /// This error is thrown when:
    /// - TLV (Tag-Length-Value) parsing fails
    /// - Response data is not in the expected format
    /// - Required fields are missing from the response
    /// - Response contains unexpected tags or values
    /// - Binary data cannot be interpreted as expected
    ///
    /// - Parameter message: A descriptive message about what parsing failed
    /// - Returns: A session-specific error describing the parsing failure
    static func responseParseError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Failed to process or encode data for use with the YubiKey.
    ///
    /// This error is thrown when:
    /// - String encoding to UTF-8 fails
    /// - Creating platform objects (SecKey, certificates) from YubiKey data fails
    /// - Data format conversion fails
    /// - Input validation fails
    /// - Data transformation operations fail
    ///
    /// - Parameter message: A descriptive message about what processing failed
    /// - Returns: A session-specific error describing the processing failure
    static func dataProcessingError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Feature is not supported on this YubiKey.
    ///
    /// This error is thrown when:
    /// - The requested operation is not available on this YubiKey model
    /// - The YubiKey firmware version doesn't support the feature
    /// - The feature requires a newer hardware revision
    /// - The operation is only available on specific YubiKey variants
    ///
    /// - Returns: A session-specific error indicating the feature is not supported
    static func featureNotSupported(
        source: SourceLocation
    ) -> Self

    /// The application is not available on this YubiKey.
    static func missingApplication(
        source: SourceLocation
    ) -> Self

    /// Invalid argument provided to a method.
    ///
    /// This error is thrown when:
    /// - Invalid parameters are passed to SDK methods
    /// - Input validation fails before YubiKey communication
    /// - Business logic constraints are violated
    /// - Required parameters are missing or invalid
    ///
    /// - Parameter message: A descriptive message about what validation failed
    /// - Returns: A session-specific error indicating invalid arguments
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
    /// Connection type is not supported on this device
    case unsupported
    /// Connection to the device was lost
    case connectionLost
    /// There is already an active connection
    case busy
    /// No YubiKey devices found or available
    case noDevicesFound
    /// Connection operation was cancelled
    case cancelled
    /// Connection was cancelled by the user
    case cancelledByUser

    /// Failed to set up the connection (with optional context and underlying error)
    case setupFailed(String? = nil, Error? = nil)
    /// Failed to transmit data (with optional context and underlying error)
    case transmitFailed(String? = nil, Error? = nil)
    /// Provided data is malformed (with optional context)
    case malformedData(String? = nil)
    /// Failed to poll for devices (with optional context)
    case pollingFailed(String? = nil)
}

// MARK: - Utility Errors

/// Errors related to encryption operations.
///
/// Low-level cryptographic operation failures.
public enum EncryptionError: Error, Sendable {
    case cryptorError(CCCryptorStatus)
    case missingData
    case unsupportedAlgorithm
}
