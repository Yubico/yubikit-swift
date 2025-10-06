// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// OATH session errors.
///
/// Handles TOTP/HOTP credential management and authentication operations.
public enum OATHSessionError: SmartCardSessionError, Sendable {
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

    // MARK: - OATH-Specific Cases

    /// Wrong password provided for authentication.
    case invalidPassword(source: SourceLocation)

    /// Failed to derive device ID.
    case failedDerivingDeviceId(source: SourceLocation)

    /// Credential not present on current YubiKey.
    case credentialNotPresentOnCurrentYubiKey(source: SourceLocation)

    case other(Error, source: SourceLocation)
}

// MARK: - Internal Convenience Methods
extension OATHSessionError {

    @inline(__always)
    static func invalidPassword(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .invalidPassword(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func failedDerivingDeviceId(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .failedDerivingDeviceId(source: SourceLocation(file: file, function: function, line: line, column: column))
    }

    @inline(__always)
    static func credentialNotPresentOnCurrentYubiKey(
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        column: Int = #column
    ) -> Self {
        .credentialNotPresentOnCurrentYubiKey(
            source: SourceLocation(file: file, function: function, line: line, column: column)
        )
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
