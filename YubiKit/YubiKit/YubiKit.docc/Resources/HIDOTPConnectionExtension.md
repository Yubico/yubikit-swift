# ``YubiKit/HIDOTPConnection``

USB HID connection to the Yubico OTP keyboard interface (macOS only).

## Overview

HIDOTPConnection establishes a connection to the YubiKey's OTP keyboard interface over USB HID.
Use it with ``YubiOTP/Session`` to configure slots and perform HMAC-SHA1 challenge-response,
including touch prompts and cancellation.

```swift
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

// Calculate a response using a slot configured for HMAC-SHA1
let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
```

macOS requires the Input Monitoring permission for the process that opens the keyboard HID device.
**Secure Event Input**, which Terminal's *Secure Keyboard Entry* setting turns on, can block access
even when the process has that permission.

> Note: This connection type is only available on macOS. ``SmartCardConnection`` reaches the same
> application on macOS and iOS, with the limitations described in ``YubiOTP/Session``.

## Topics

### Creating a Connection

- ``init()``
- ``makeConnection()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Report Communication

- ``reportSize``
- ``send(_:)``
- ``receive()``

### Errors

- ``OTPConnectionError``
