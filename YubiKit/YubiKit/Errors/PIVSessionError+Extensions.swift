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

extension PIVSessionError {

    // MARK: - PIV-Specific Convenience Methods

    @inline(__always)
    static func unknownKeyType(
        _ keyType: UInt8,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .unknownKeyType(keyType, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func invalidPin(
        _ retries: Int,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        Self.invalidPin(retries, source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func pinLocked(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .pinLocked(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func authenticationFailed(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .authenticationFailed(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func invalidKeyLength(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .invalidKeyLength(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func invalidDataSize(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .invalidDataSize(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func gzip(
        _ error: Error,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .gzip(error, source: SourceLocation(file: file, function: function, line: line, column: column))
    }
}
