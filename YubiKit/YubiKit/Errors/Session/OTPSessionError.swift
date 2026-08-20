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

/// Errors that occur during Yubico OTP session operations over the keyboard HID transport.
public protocol OTPSessionError: SessionError {

    // MARK: - OTP-Specific Error Factory Methods

    /// Operation timed out — either waiting for the key to become ready, or waiting for touch.
    static func timeout(source: SourceLocation) -> Self

    /// The YubiKey rejected the command.
    ///
    /// The key answered with an unchanged programming sequence and no data, which is how it
    /// reports a refused slot command (a bad access code, or a command the firmware does not
    /// implement).
    static func commandRejected(_ message: String, source: SourceLocation) -> Self

    /// Connection-level error from the underlying transport.
    static func otpConnectionError(_ error: OTPConnectionError, source: SourceLocation) -> Self
}
