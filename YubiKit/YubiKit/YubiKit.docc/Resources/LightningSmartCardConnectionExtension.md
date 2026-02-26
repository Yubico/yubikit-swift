# ``YubiKit/LightningSmartCardConnection``

Lightning connection to a YubiKey 5Ci (iOS only).

## Overview

LightningSmartCardConnection establishes a connection to a YubiKey 5Ci via the Lightning
port using the External Accessory framework. This requires the `com.yubico.ylp` protocol
to be listed in your app's supported external accessory protocols.

Lightning connections are persistent and remain active until the YubiKey is unplugged.

```swift
let connection = try await LightningSmartCardConnection()
let session = try await OATHSession.makeSession(connection: connection)
// ... perform operations ...
```

## Topics

### Creating a Connection

- ``init()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Sending Data

- ``send(data:)``

### Errors

- ``SmartCardConnectionError``
