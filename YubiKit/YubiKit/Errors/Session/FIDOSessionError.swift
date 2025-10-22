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
protocol FIDOSessionError: SessionError {

    // MARK: - FIDO-Specific Error Factory Methods

    /// Operation timed out waiting for a response from the authenticator.
    static func timeout(source: SourceLocation) -> Self

    /// CTAP INIT handshake failed.
    static func initializationFailed(_ message: String, source: SourceLocation) -> Self

    /// HID transport error returned by the authenticator.
    static func hidError(_ error: CTAP.HIDError, source: SourceLocation) -> Self

    /// Connection-level error from the underlying transport.
    static func connectionError(_ error: FIDOConnectionError, source: SourceLocation) -> Self
}

// MARK: - Internal Convenience Methods
extension FIDOSessionError {

    @inline(__always)
    static func cryptoError(
        _ message: String,
        error: Error? = nil,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .cryptoError(
            message,
            error: error,
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
    }

    @inline(__always)
    static func responseParseError(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .responseParseError(message, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func dataProcessingError(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .dataProcessingError(
            message,
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
    }

    @inline(__always)
    static func illegalArgument(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .illegalArgument(message, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func featureNotSupported(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .featureNotSupported(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func timeout(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .timeout(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func initializationFailed(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .initializationFailed(
            message,
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
    }

    @inline(__always)
    static func hidError(
        _ error: CTAP.HIDError,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .hidError(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func connectionError(
        _ error: FIDOConnectionError,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .connectionError(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }
}
