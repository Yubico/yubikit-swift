# ``YubiKit/FIDOConnection``

Protocol for FIDO2/CTAP connections to a YubiKey.

## Overview

FIDOConnection defines the interface for low-level FIDO/CTAP communication with a YubiKey.
Unlike ``SmartCardConnection`` (which uses APDU commands over CCID), FIDOConnection uses
the CTAP HID protocol for FIDO2 operations.

Use ``HIDFIDOConnection`` on macOS for USB HID connections. On iOS, use
``NFCSmartCardConnection`` instead - the SDK handles the protocol translation internally.

```swift
// macOS: USB HID connection
let connection = try await HIDFIDOConnection()
let session = try await CTAP2.Session.makeSession(connection: connection)

// iOS: Use NFC (CTAP over NFC is handled automatically)
let connection = try await NFCSmartCardConnection()
let session = try await CTAP2.Session.makeSession(connection: connection)
```

## Topics

### Creating a Connection

- ``init()``
- ``makeConnection()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Sending Data

- ``mtu``
- ``send(_:)``
- ``receive()``

### Errors

- ``FIDOConnectionError``
