# ``YubiKit/OTPConnection``

Protocol for connections to the Yubico OTP keyboard interface on a YubiKey.

## Overview

OTPConnection defines the interface for low-level Yubico OTP communication with a YubiKey. All
traffic moves in fixed 8-byte HID feature reports; the 70-byte command frame, its CRC, and
programming-sequence tracking are handled above this layer.

This is the keyboard HID interface (usage page `0x01`, usage `0x06`), not the FIDO HID interface
used by ``FIDOConnection``. A YubiKey only exposes it when the Yubico OTP application is enabled
over USB.

Use ``HIDOTPConnection`` on macOS. Everywhere else — and over NFC — reach the same application
with a ``SmartCardConnection``.

```swift
// macOS: the OTP keyboard interface
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

// Any platform, including NFC: the same application over CCID
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
