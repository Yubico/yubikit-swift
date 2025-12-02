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

/// Errors that can occur during FIDO2/CTAP session operations.
extension CTAP2 {
    enum SessionError: FIDOSessionError, SmartCardSessionError, CBORError, CTAPError, Sendable {

        // MARK: - Common Session Errors

        /// A requested feature is not supported by this YubiKey.
        case featureNotSupported(source: SourceLocation)

        /// Failed to parse the response from the YubiKey.
        case responseParseError(_ message: String, source: SourceLocation)

        /// An illegal argument was provided.
        case illegalArgument(_ message: String, source: SourceLocation)

        /// Error processing data.
        case dataProcessingError(_ message: String, source: SourceLocation)

        /// A cryptographic operation failed.
        case cryptoError(_ message: String, error: Swift.Error?, source: SourceLocation)

        // MARK: - FIDO-Specific Errors

        /// FIDO connection error.
        case fidoConnectionError(_ error: FIDOConnectionError, source: SourceLocation)

        /// CTAP HID-level error.
        case hidError(_ error: CTAP2.HIDError, source: SourceLocation)

        /// FIDO initialization failed.
        case initializationFailed(_ message: String, source: SourceLocation)

        /// Operation timed out.
        case timeout(source: SourceLocation)

        /// CTAP protocol-level error.
        case ctapError(_ error: CTAP2.Error, source: SourceLocation)

        /// CBOR encoding/decoding error.
        case cborError(_ error: CBOR.Error, source: SourceLocation)

        /// PIN/UV auth protocol error.
        case authError(_ error: PinUVAuth.Error, source: SourceLocation)

        // MARK: - SmartCard-Specific Errors

        /// SmartCard APDU response indicated an error.
        case failedResponse(_ response: Response, source: SourceLocation)

        /// SCP (Secure Channel Protocol) error.
        case scpError(_ error: SCPError, source: SourceLocation)

        /// SmartCard connection error.
        case connectionError(_ error: SmartCardConnectionError, source: SourceLocation)

        // MARK: - Protocol Conformance

        public var responseStatus: ResponseStatus? {
            guard case let .failedResponse(response, _) = self else { return nil }
            return response.responseStatus
        }
    }
}
