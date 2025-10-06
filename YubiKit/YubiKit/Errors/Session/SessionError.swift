/// Common protocol for all session error types.
/// Enforces common error cases that all sessions must handle.
public protocol SessionError: Error, Sendable {
    /// Encryption or cryptographic operation failed.
    static func cryptoError(
        _ message: String,
        error: Error?,
        source: SourceLocation
    ) -> Self

    /// Failed to parse data received from the YubiKey.
    static func responseParseError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Failed to process or encode data for use with the YubiKey.
    static func dataProcessingError(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Invalid argument provided to a method.
    static func illegalArgument(
        _ message: String,
        source: SourceLocation
    ) -> Self

    /// Feature is not supported on this YubiKey.
    static func featureNotSupported(
        source: SourceLocation
    ) -> Self
}
