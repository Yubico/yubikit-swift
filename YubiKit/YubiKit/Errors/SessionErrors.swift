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

// MARK: - Security Domain Errors

/// Security Domain (SCP) errors.
///
/// SCP (Secure Channel Protocol) provides encrypted communication with YubiKeys.
/// These errors represent failures in the cryptographic security layer.
public enum SCPError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case encryptionFailed(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    public static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self {
        error
    }

    // MARK: - SCP-Specific Cases

    /// Secure channel is required for this operation.
    case secureChannelRequired(source: SourceLocation)
}

// MARK: - Application Session Errors

/// Management session errors.
///
/// Handles device configuration, capability detection, and general YubiKey management operations.
public enum ManagementSessionError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case encryptionFailed(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    // MARK: - Management-Specific Cases
    // ...
}

// MARK: - OATH Session Errors

/// OATH session errors.
///
/// Handles TOTP/HOTP credential management and authentication operations.
public enum OATHSessionError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case encryptionFailed(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    // MARK: - OATH-Specific Cases

    /// Wrong password provided for authentication.
    case invalidPassword(source: SourceLocation)

    /// Failed to derive device ID.
    case failedDerivingDeviceId(source: SourceLocation)

    /// Credential not present on current YubiKey.
    case credentialNotPresentOnCurrentYubiKey(source: SourceLocation)
}

// MARK: - PIV Session Errors

/// PIV session errors.
///
/// Handles smart card operations including certificate management, key generation,
/// digital signatures, and PIN/PUK authentication.
public enum PIVSessionError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case encryptionFailed(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    // MARK: - PIV-Specific Cases

    /// Unknown key type encountered.
    case unknownKeyType(UInt8, source: SourceLocation)

    /// Invalid PIN with remaining retries.
    case invalidPin(_ retries: Int, source: SourceLocation)

    /// PIN is locked and requires PUK to reset.
    case pinLocked(source: SourceLocation)

    /// Authentication failed.
    case authenticationFailed(source: SourceLocation)

    /// Invalid key length for operation.
    case invalidKeyLength(source: SourceLocation)

    /// Invalid data size for operation.
    case invalidDataSize(source: SourceLocation)

    /// Gzip compression/decompression failed.
    case gzip(Error, source: SourceLocation)
}
