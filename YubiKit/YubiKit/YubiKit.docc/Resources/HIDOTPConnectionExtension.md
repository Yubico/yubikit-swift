# ``YubiKit/HIDOTPConnection``

USB HID connection to the Yubico OTP keyboard interface (macOS only).

## Overview

HIDOTPConnection exchanges 8-byte feature reports with the keyboard HID interface of the YubiKey.
It is the only transport that reports a pending touch during a challenge, so an app can prompt the
user and cancel the challenge.

```swift
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)
let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
```

macOS requires the Input Monitoring permission for the process that opens the keyboard HID device.
**Secure Event Input**, which Terminal's *Secure Keyboard Entry* setting turns on, can block access
even when the process has that permission.

> Note: This connection type is only available on macOS. ``SmartCardConnection`` reaches the same
> application on all platforms and over NFC.

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
