# ``YubiKit/OTPConnection``

Protocol for connections to the Yubico OTP keyboard interface on a YubiKey.

## Overview

OTPConnection defines the interface for low-level communication with the YubiKey's OTP keyboard
interface. Use ``YubiOTP/Session`` to configure slots and perform HMAC-SHA1 challenge-response.
The Yubico OTP application must be enabled over USB.

Use ``HIDOTPConnection`` on macOS. On iOS and over NFC, use a ``SmartCardConnection`` to reach the
same application.

```swift
// macOS: the OTP keyboard interface
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)
```

```swift
// iOS: the same application over NFC
let connection = try await NFCSmartCardConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)
```

## Topics

### Creating a Connection

- ``init()``
- ``makeConnection()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Sending Data

- ``reportSize``
- ``send(_:)``
- ``receive()``

### Errors

- ``OTPConnectionError``
