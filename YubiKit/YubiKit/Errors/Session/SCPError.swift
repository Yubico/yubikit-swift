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

/// Security Domain (SCP) errors.
///
/// SCP (Secure Channel Protocol) provides encrypted communication with YubiKeys.
/// These errors represent failures in the cryptographic security layer.
public enum SCPError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case cryptoError(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    public static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self {
        error
    }

    public var responseStatus: ResponseStatus? {
        guard case let .failedResponse(status, _) = self else {
            return nil
        }
        return status
    }

    // MARK: - SCP-Specific Cases

    /// Secure channel is required for this operation.
    case secureChannelRequired(source: SourceLocation)

    case other(Error, source: SourceLocation)
}

// MARK: - Internal Convenience Methods
extension SCPError {

    @inline(__always)
    static func secureChannelRequired(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .secureChannelRequired(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func other(
        _ error: Error,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .other(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }
}
