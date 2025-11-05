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

/// Management session errors.
///
/// Handles device configuration, capability detection, and general YubiKey management operations.
public enum ManagementSessionError: FIDOSessionError, SmartCardSessionError, Sendable {
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case fidoConnectionError(FIDOConnectionError, source: SourceLocation)

    case featureNotSupported(source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case cryptoError(String, error: Swift.Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    case timeout(source: SourceLocation)
    case initializationFailed(_ message: String, source: SourceLocation)
    case hidError(_ error: CTAP.HIDError, source: SourceLocation)

    public var responseStatus: ResponseStatus? {
        guard case let .failedResponse(status, _) = self else { return nil }
        return status
    }

    // MARK: - Management-Specific Cases
    case other(Error, source: SourceLocation)
}
