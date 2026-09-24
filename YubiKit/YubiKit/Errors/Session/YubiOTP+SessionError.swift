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

extension YubiOTP {
    /// Errors thrown by ``YubiOTP/Session`` operations.
    ///
    /// This type includes failures from both the OTP keyboard HID and SmartCard transports.
    public enum SessionError: SmartCardSessionError, Sendable {

        // MARK: - Common Session Errors

        /// The connected YubiKey does not support the requested feature.
        case featureNotSupported(source: SourceLocation)

        /// A response from the YubiKey could not be parsed.
        case responseParseError(String, source: SourceLocation)

        /// An argument is invalid for the requested operation.
        case illegalArgument(String, source: SourceLocation)

        /// Response data could not be processed.
        case dataProcessingError(String, source: SourceLocation)

        /// A cryptographic operation failed.
        case cryptoError(String, error: Swift.Error?, source: SourceLocation)

        // MARK: - SmartCard-Specific Errors

        /// A SmartCard transport operation failed.
        case connectionError(SmartCardConnectionError, source: SourceLocation)

        /// The YubiKey returned an unsuccessful SmartCard response.
        case failedResponse(Response, source: SourceLocation)

        /// Secure Channel Protocol setup or communication failed.
        case scpError(SCPError, source: SourceLocation)

        // MARK: - OTP-Specific Errors

        /// An OTP keyboard HID transport operation failed.
        case otpConnectionError(OTPConnectionError, source: SourceLocation)

        /// The YubiKey did not accept the slot command.
        case commandRejected(String, source: SourceLocation)

        /// The YubiKey did not answer in time, or the touch did not occur in time.
        case timeout(source: SourceLocation)

        /// The operation was cancelled before it completed.
        case cancelled(source: SourceLocation)

        // MARK: - Protocol Conformance

        /// The status word of a failed SmartCard response, when available.
        public var responseStatus: Response.Status? {
            guard case let .failedResponse(response, _) = self else { return nil }
            return response.responseStatus
        }
    }
}
