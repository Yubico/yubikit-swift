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

/// Source location information for debugging and error reporting.
public struct SourceLocation: Sendable {
    /// The source file where the error occurred.
    public let file: String
    /// The function where the error occurred.
    public let function: String
    /// The line number where the error occurred.
    public let line: Int
    /// The column number where the error occurred.
    public let column: Int

    @inline(__always)
    init(
        file: String,
        function: String,
        line: Int,
        column: Int
    ) {
        self.file = file
        self.function = function
        self.line = line
        self.column = column
    }

    /// Captures the current source location.
    ///
    /// Use this static function to automatically capture the file, function, line, and column
    /// where an error is thrown.
    ///
    /// Example:
    /// ```swift
    /// throw Error.featureNotSupported(source: .here())
    /// ```
    @inline(__always)
    public static func here(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        Self(file: file, function: function, line: line, column: column)
    }
}
