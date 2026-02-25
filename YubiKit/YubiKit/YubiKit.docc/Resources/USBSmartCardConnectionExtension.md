# ``YubiKit/USBSmartCardConnection``

USB SmartCard (CCID) connection to a YubiKey.

## Overview

USBSmartCardConnection establishes a connection to a YubiKey via USB using the SmartCard
(CCID) interface.

USB connections are persistent and remain active until the YubiKey is unplugged or
the connection is explicitly closed.

```swift
let connection = try await USBSmartCardConnection()
let session = try await PIVSession.makeSession(connection: connection)
// ... perform operations ...

// Wait for disconnect (e.g., user unplugs YubiKey)
let error = await connection.waitUntilClosed()
```

## Topics

### Creating a Connection

- ``init()``
- ``init(slot:)``
- ``availableDevices()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Sending Data

- ``send(data:)``

### Errors

- ``SmartCardConnectionError``
