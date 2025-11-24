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

/// Errors that occur during FIDO session operations.
///
/// These errors represent both local transport issues and errors returned by the authenticator.
public protocol FIDOSessionError: SessionError {

    // MARK: - FIDO-Specific Error Factory Methods

    /// Operation timed out waiting for a response from the authenticator.
    static func timeout(source: SourceLocation) -> Self

    /// CTAP INIT handshake failed.
    static func initializationFailed(_ message: String, source: SourceLocation) -> Self

    /// HID transport error returned by the authenticator.
    static func hidError(_ error: CTAP2.HIDError, source: SourceLocation) -> Self

    /// Connection-level error from the underlying transport.
    static func fidoConnectionError(_ error: FIDOConnectionError, source: SourceLocation) -> Self
}
