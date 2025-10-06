// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// PIV session errors.
///
/// Handles smart card operations including certificate management, key generation,
/// digital signatures, and PIN/PUK authentication.
public enum PIVSessionError: SmartCardSessionError, Sendable {
    // MARK: - SessionError Protocol Cases
    case featureNotSupported(source: SourceLocation)
    case connectionError(SmartCardConnectionError, source: SourceLocation)
    case failedResponse(ResponseStatus, source: SourceLocation)
    case scpError(SCPError, source: SourceLocation)
    case cryptoError(String, error: Error?, source: SourceLocation)
    case responseParseError(String, source: SourceLocation)
    case dataProcessingError(String, source: SourceLocation)
    case illegalArgument(String, source: SourceLocation)

    public var responseStatus: ResponseStatus? {
        guard case let .failedResponse(status, _) = self else {
            return nil
        }
        return status
    }

    // MARK: - PIV-Specific Cases

    /// Unknown key type encountered.
    case unknownKeyType(UInt8, source: SourceLocation)

    /// Invalid PIN with remaining retries.
    case invalidPin(_ retries: Int, source: SourceLocation)

    /// PIN is locked and requires PUK to reset.
    case pinLocked(source: SourceLocation)

    /// Authentication failed.
    case authenticationFailed(source: SourceLocation)

    /// Invalid key length for operation.
    case invalidKeyLength(source: SourceLocation)

    /// Invalid data size for operation.
    case invalidDataSize(source: SourceLocation)

    /// Gzip compression/decompression failed.
    case gzip(Error, source: SourceLocation)

    case other(Error, source: SourceLocation)
}

// MARK: - Internal Convenience Methods
extension PIVSessionError {

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
        Self.invalidPin(
            retries,
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
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
