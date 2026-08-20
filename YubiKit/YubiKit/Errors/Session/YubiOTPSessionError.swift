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

/// Yubico OTP session errors.
///
/// The YubiOTP application is reachable over two transports, so this type carries both the OTP
/// keyboard HID cases and the SmartCard (CCID) cases.
public enum YubiOTPSessionError: OTPSessionError, SmartCardSessionError, Sendable {
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case otpConnectionError(OTPConnectionError, source: SourceLocation)

    case featureNotSupported(source: SourceLocation)
    case failedResponse(Response, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case cryptoError(String, error: Swift.Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    case timeout(source: SourceLocation)

    // MARK: - OTP-Specific Cases

    /// The YubiKey rejected the slot command.
    case commandRejected(String, source: SourceLocation)

    public var responseStatus: Response.Status? {
        guard case let .failedResponse(response, _) = self else { return nil }
        return response.responseStatus
    }
}
