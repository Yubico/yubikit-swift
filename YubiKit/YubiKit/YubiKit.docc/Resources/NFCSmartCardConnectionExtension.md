# ``YubiKit/NFCSmartCardConnection``

NFC connection to a YubiKey (iOS only).

## Overview

NFCSmartCardConnection establishes a connection to a YubiKey via NFC. The connection
presents the system NFC dialog and waits for the user to tap their YubiKey.

NFC connections are short-lived due to iOS timeout constraints. Perform operations quickly
and close the connection with a user-visible message.

```swift
let connection = try await NFCSmartCardConnection(
    alertMessage: "Hold your YubiKey near the phone"
)
let session = try await OATHSession.makeSession(connection: connection)
let codes = try await session.calculateCredentialCodes()
await connection.close(message: "Codes retrieved")
```

## Topics

### Creating a Connection

- ``init()``
- ``init(alertMessage:)``
- ``setAlertMessage(_:)``

### Connection Lifecycle

- ``close(error:)``
- ``close(message:)``
- ``waitUntilClosed()``

### Sending Data

- ``send(data:)``

### Errors

- ``SmartCardConnectionError``
