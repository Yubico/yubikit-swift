# ``YubiKit/SmartCardConnection``

Protocol for SmartCard (CCID) connections to a YubiKey.

## Overview

SmartCardConnection is the base protocol for all CCID-based connections. Concrete implementations
include ``NFCSmartCardConnection``, ``USBSmartCardConnection``, and ``LightningSmartCardConnection``.

Connections provide exclusive access to the YubiKey and must be explicitly closed when done.
Use connections to create sessions for specific YubiKey applications like OATH, PIV, or Management.

```swift
let connection = try await NFCSmartCardConnection()
let session = try await OATHSession.makeSession(connection: connection)
// ... use session ...
await connection.close(error: nil)
```

## Topics

### Creating a Connection

- ``makeConnection()``

### Connection Lifecycle

- ``Connection/close(error:)``
- ``Connection/waitUntilClosed()``

### Sending Data

- ``send(data:)``

### Errors

- ``SmartCardConnectionError``
- ``Response/Status/Code``
