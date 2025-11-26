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

/// Common protocol for all smart card session error types.
/// Enforces common error cases that all smart card sessions must handle.
public protocol SmartCardSessionError: SessionError {

    // NEXTMAJOR: connectionError should be renamed to `smartCardConnectionError`

    /// Connection error occurred during communication with the YubiKey.
    static func connectionError(
        _ error: SmartCardConnectionError,
        source: SourceLocation
    ) -> Self

    /// Response status error that couldn't be handled specifically by the session.
    static func failedResponse(
        _ response: Response,
        source: SourceLocation
    ) -> Self

    /// SCP-level error occurred during secure channel operations.
    static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self

    /// The response status code from the YubiKey, if this error was caused by a failed response.
    /// Returns `nil` for errors that don't originate from a response status (connection errors, crypto errors).
    var responseStatus: ResponseStatus? { get }
}
