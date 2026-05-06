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

// MARK: - WebAuthn Error

extension WebAuthn {

    /// Errors that can occur during WebAuthn client operations.
    public enum ClientError: Swift.Error, Sendable {
        /// The request parameters are invalid (e.g., RP ID mismatch, public suffix).
        case invalidRequest(_ message: String, source: SourceLocation)
        /// None of the requested algorithms are supported by the authenticator.
        case unsupportedAlgorithm(source: SourceLocation)
        /// A credential in the exclude list already exists on this authenticator.
        case credentialExcluded(source: SourceLocation)
        /// The operation was cancelled by the user or client.
        case cancelled(source: SourceLocation)
        /// The operation timed out waiting for user interaction.
        case timeout(source: SourceLocation)
        /// A PIN attempt was rejected but retries are still available on the
        /// authenticator. Re-invoke the operation with a fresh PIN.
        case pinRejected(retriesRemaining: Int, source: SourceLocation)
        /// A built-in UV attempt failed but retries are still available on
        /// the authenticator. Re-invoke the operation to retry UV (or supply
        /// a PIN via a fresh ``Authorization``).
        case uvRejected(retriesRemaining: Int, source: SourceLocation)
        /// Built-in UV is locked out for this authenticator. Re-invoke using
        /// the PIN path; a successful PIN validation via ClientPin unlocks
        /// built-in UV (only that or a factory reset will).
        case uvBlocked(source: SourceLocation)
        /// The PIN is blocked due to too many failed attempts. Factory reset required.
        case pinBlocked(source: SourceLocation)
        /// PIN authentication is temporarily blocked. Reinsert the authenticator.
        case pinAuthBlocked(source: SourceLocation)
        /// No PIN is configured on this authenticator.
        case pinNotSet(source: SourceLocation)
        /// The PIN does not meet the authenticator's complexity policy.
        case pinComplexity(source: SourceLocation)
        /// The authenticator requires a PIN change before further PIN-using operations.
        case forcePinChange(source: SourceLocation)
        /// The PIN token expired. Retry the operation.
        case pinTokenExpired(source: SourceLocation)
        /// The requested feature is not supported by this authenticator.
        case notSupported(_ message: String, source: SourceLocation)
        /// The authenticator's credential storage is full.
        case storageFull(source: SourceLocation)
        /// No matching credentials exist on this authenticator.
        case noCredentials(source: SourceLocation)
        /// The authenticator is not available (disconnected or communication error).
        case authenticatorNotAvailable(source: SourceLocation)
        /// A CTAP2 error not mapped to a specific WebAuthn error.
        case ctapError(_ error: CTAP2.SessionError, source: SourceLocation)
        /// An unexpected internal error occurred.
        case internalError(_ message: String, source: SourceLocation)
    }
}

// MARK: - CTAP Error Conversion

extension WebAuthn.ClientError {

    init(_ ctapError: CTAP2.SessionError, source: SourceLocation = .here()) {
        switch ctapError {
        case .ctapError(let code, _):
            switch code {
            case .credentialExcluded: self = .credentialExcluded(source: source)
            case .noCredentials: self = .noCredentials(source: source)
            case .operationDenied, .keepaliveCancel: self = .cancelled(source: source)
            case .actionTimeout, .userActionTimeout: self = .timeout(source: source)
            case .uvBlocked: self = .uvBlocked(source: source)
            case .pinBlocked: self = .pinBlocked(source: source)
            case .pinAuthBlocked: self = .pinAuthBlocked(source: source)
            case .pinPolicyViolation: self = .pinComplexity(source: source)
            case .pinNotSet: self = .pinNotSet(source: source)
            case .pinTokenExpired: self = .pinTokenExpired(source: source)
            case .unsupportedAlgorithm: self = .unsupportedAlgorithm(source: source)
            case .keyStoreFull, .largeBlobStorageFull: self = .storageFull(source: source)
            case .pinInvalid, .uvInvalid, .puatRequired:
                preconditionFailure("CTAP \(code) must be resolved by Client+UserVerification, not here")
            default: self = .ctapError(ctapError, source: source)
            }
        case .connectionError:
            self = .authenticatorNotAvailable(source: source)
        case .featureNotSupported:
            self = .notSupported("Feature not supported by authenticator", source: source)
        default:
            self = .ctapError(ctapError, source: source)
        }
    }
}
