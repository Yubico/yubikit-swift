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

// MARK: - SessionError Factory Methods

extension SmartCardSessionError {
    @inline(__always)
    static func connectionError(
        _ error: SmartCardConnectionError,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .connectionError(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func failedResponse(
        _ responseStatus: ResponseStatus,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .failedResponse(
            responseStatus,
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
    }

    @inline(__always)
    static func encryptionFailed(
        _ message: String,
        error: Error? = nil,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .encryptionFailed(
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
    static func featureNotSupported(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .featureNotSupported(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func missingApplication(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .missingApplication(source: SourceLocation(file: file, function: function, line: line, column: column))
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
    static func scpError(
        _ error: SCPError,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .scpError(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }
}
