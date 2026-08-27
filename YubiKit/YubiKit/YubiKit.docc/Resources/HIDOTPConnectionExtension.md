# ``YubiKit/HIDOTPConnection``

USB HID connection to the Yubico OTP keyboard interface (macOS only).

## Overview

HIDOTPConnection exchanges 8-byte feature reports with the YubiKey's keyboard HID interface. It is
the only transport that can report a pending touch while a challenge is in flight, so a
touch-triggered slot can prompt the user and be cancelled.

```swift
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

for try await status in await session.calculateHMACSHA1(challenge: challenge, in: .two) {
    switch status {
    case .processing:
        showSpinner()
    case .waitingForUser(let cancel):
        showTouchPrompt(onCancel: { Task { await cancel() } })
    case .finished(let response):
        return response
    }
}
```

> Important: **Secure Event Input** blocks this connection outright. It is a system-wide flag —
> asserted by Terminal's *Secure Keyboard Entry* setting, by password fields, and by the lock
> screen — and while it is held, every unprivileged process reading a keyboard HID device is
> refused. Check with `ioreg -l -d 1 -k IOConsoleUsers | grep kCGSSessionSecureInputPID`, which
> names the process holding it.

> Note: This connection type is only available on macOS. ``SmartCardConnection`` reaches the same
> YubiOTP application on every platform and over NFC, with none of these requirements.

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
