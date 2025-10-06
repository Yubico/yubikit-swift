// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Common protocol for all smart card session error types.
/// Enforces common error cases that all smart card sessions must handle.
public protocol SmartCardSessionError: SessionError {
    /// Connection error occurred during communication with the YubiKey.
    static func connectionError(
        _ error: SmartCardConnectionError,
        source: SourceLocation
    ) -> Self

    /// Response status error that couldn't be handled specifically by the session.
    static func failedResponse(
        _ responseStatus: ResponseStatus,
        source: SourceLocation
    ) -> Self

    /// SCP-level error occurred during secure channel operations.
    static func scpError(
        _ error: SCPError,
        source: SourceLocation
    ) -> Self

    /// The response status code from the YubiKey, if this error was caused by a failed response.
    /// Returns `nil` for errors that don't originate from a response status (connection errors, crypto errors).
    var responseStatus: ResponseStatus? { get }
}

// MARK: - Internal Convenience Methods
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
    static func featureNotSupported(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .featureNotSupported(source: SourceLocation(file: file, function: function, line: line, column: column))
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
