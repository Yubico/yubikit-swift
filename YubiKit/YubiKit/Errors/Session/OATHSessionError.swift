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

/// OATH session errors.
///
/// Handles TOTP/HOTP credential management and authentication operations.
public enum OATHSessionError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(Response, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case cryptoError(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    public var responseStatus: ResponseStatus? {
        guard case let .failedResponse(response, _) = self else {
            return nil
        }
        return response.responseStatus
    }

    // MARK: - OATH-Specific Cases

    /// Wrong password provided for authentication.
    case invalidPassword(source: SourceLocation)

    /// Failed to derive device ID.
    case failedDerivingDeviceId(source: SourceLocation)

    /// Credential not present on current YubiKey.
    case credentialNotPresentOnCurrentYubiKey(source: SourceLocation)

    case other(Error, source: SourceLocation)
}
