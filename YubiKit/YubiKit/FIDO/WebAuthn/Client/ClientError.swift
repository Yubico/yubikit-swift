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

extension WebAuthn {

    /// Errors that can occur during WebAuthn client operations.
    public enum ClientError: Error, Sendable {
        case invalidRequest(_ message: String, source: SourceLocation)
        case unsupportedAlgorithm(source: SourceLocation)
        case credentialExcluded(source: SourceLocation)
        case noCredentials(source: SourceLocation)
        case cancelled(source: SourceLocation)
        case timeout(source: SourceLocation)
        case userVerificationFailed(retriesRemaining: Int?, source: SourceLocation)
        case invalidPIN(retriesRemaining: Int, source: SourceLocation)
        case pinBlocked(source: SourceLocation)
        case pinAuthBlocked(source: SourceLocation)
        case pinNotSet(source: SourceLocation)
        case pinRequired(source: SourceLocation)
        case pinTokenExpired(source: SourceLocation)
        case notSupported(_ message: String, source: SourceLocation)
        case storageFull(source: SourceLocation)
        case authenticatorNotAvailable(source: SourceLocation)
        case ctapError(_ error: CTAP2.SessionError, source: SourceLocation)
        case internalError(_ message: String, source: SourceLocation)
    }
}

extension WebAuthn.ClientError {

    init(_ ctapError: CTAP2.SessionError, source: SourceLocation = .here()) {
        switch ctapError {
        case .ctapError(let code, _):
            switch code {
            case .credentialExcluded: self = .credentialExcluded(source: source)
            case .noCredentials: self = .noCredentials(source: source)
            case .operationDenied, .keepaliveCancel: self = .cancelled(source: source)
            case .actionTimeout, .userActionTimeout: self = .timeout(source: source)
            case .pinBlocked: self = .pinBlocked(source: source)
            case .pinAuthBlocked: self = .pinAuthBlocked(source: source)
            case .pinNotSet: self = .pinNotSet(source: source)
            case .pinTokenExpired: self = .pinTokenExpired(source: source)
            case .unsupportedAlgorithm: self = .unsupportedAlgorithm(source: source)
            case .keyStoreFull: self = .storageFull(source: source)
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
