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

/// Errors that occur during OTP keyboard HID session operations.
public protocol OTPSessionError: SessionError {
    /// Connection-level error from the OTP transport.
    static func otpConnectionError(_ error: OTPConnectionError, source: SourceLocation) -> Self

    /// The YubiKey did not accept the command.
    static func commandRejected(_ message: String, source: SourceLocation) -> Self

    /// The operation timed out waiting for a response or touch.
    static func timeout(source: SourceLocation) -> Self

    /// The operation was cancelled before completion.
    static func cancelled(source: SourceLocation) -> Self
}
