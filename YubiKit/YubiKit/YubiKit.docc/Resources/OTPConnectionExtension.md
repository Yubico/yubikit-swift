# ``YubiKit/OTPConnection``

Protocol for connections to the Yubico OTP keyboard interface on a YubiKey.

## Overview

OTPConnection moves fixed 8-byte HID feature reports. ``YubiOTP/Session`` builds the 70-byte
command frames above this layer.

This is the keyboard HID interface (usage page `0x01`, usage `0x06`), not the FIDO HID interface
of ``FIDOConnection``. A YubiKey exposes it only when the Yubico OTP application is enabled over USB.

Use ``HIDOTPConnection`` on macOS. On iOS and over NFC, use a ``SmartCardConnection`` to reach the
same application.

```swift
// macOS: the OTP keyboard interface
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

// iOS: the same application over NFC
let nfcConnection = try await NFCSmartCardConnection()
let nfcSession = try await YubiOTP.Session.makeSession(connection: nfcConnection)
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
