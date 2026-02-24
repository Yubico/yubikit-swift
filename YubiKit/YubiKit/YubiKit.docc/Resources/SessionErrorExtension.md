# ``YubiKit/CTAP2/SessionError``

Errors thrown by CTAP2 session operations.

## Overview

This error type encompasses all possible failures during CTAP2 operations,
including protocol errors from the authenticator, transport errors, and
local processing errors.

## Topics

### Protocol Errors

- ``ctapError(_:source:)``
- ``hidError(_:source:)``
- ``extensionNotSupported(_:source:)``

### Processing Errors

- ``responseParseError(_:source:)``
- ``illegalArgument(_:source:)``
- ``dataProcessingError(_:source:)``
- ``compressionError(_:source:)``
- ``cryptoError(_:error:source:)``

### Connection Errors

- ``fidoConnectionError(_:source:)``
- ``connectionError(_:source:)``
- ``initializationFailed(_:source:)``
- ``timeout(source:)``

### Other Errors

- ``featureNotSupported(source:)``
- ``failedResponse(_:source:)``
- ``scpError(_:source:)``
- ``cborError(_:source:)``
