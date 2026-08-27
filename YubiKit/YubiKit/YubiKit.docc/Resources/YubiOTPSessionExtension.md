# ``YubiKit/YubiOTP/Session``

Session for the Yubico OTP application on the YubiKey.

## Overview

YubiOTP.Session programs and challenges the YubiKey's two OTP slots. The application is reachable
two ways and the session speaks both: over the OTP keyboard HID interface (``OTPConnection``,
macOS only) and over SmartCard (``SmartCardConnection``, including NFC). Behaviour is identical
whichever transport drives it.

```swift
let connection = try await USBSmartCardConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

print("Serial: \(try await session.getSerialNumber())")

// Program slot 2 for HMAC-SHA1 challenge-response
try await session.putConfiguration(
    YubiOTP.HMACSHA1SlotConfiguration(key: secret),
    in: .two
)

// Challenge it
let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
```

A slot programmed with `requireTouch` does not answer until the button is pressed. Iterate the
returned ``YubiOTP/StatusStream`` to prompt for the touch and to offer cancellation, or read
``YubiOTP/StatusStream/value`` when no such feedback is needed.

> Note: Only the OTP keyboard transport reports touch progress. Over SmartCard the exchange is a
> single blocking APDU.

## Topics

### Creating a Session

- ``makeSession(connection:)``
- ``makeSession(connection:scpKeyParams:)``

### Reading Device State

- ``version``
- ``configState``
- ``getSerialNumber()``
- ``supports(_:)``

### Programming Slots

- ``putConfiguration(_:in:accessCode:currentAccessCode:)``
- ``updateConfiguration(_:in:accessCode:currentAccessCode:)``
- ``deleteConfiguration(in:currentAccessCode:)``
- ``swapConfigurations()``
- ``setScanMap(_:currentAccessCode:)``
- ``setNDEFConfiguration(in:uri:type:currentAccessCode:)``

### Challenge-Response

- ``calculateHMACSHA1(challenge:in:)``

### Slot Configurations

- ``YubiOTP/SlotConfiguration``
- ``YubiOTP/HMACSHA1SlotConfiguration``
- ``YubiOTP/YubicoOTPSlotConfiguration``
- ``YubiOTP/HOTPSlotConfiguration``
- ``YubiOTP/StaticPasswordSlotConfiguration``
- ``YubiOTP/StaticTicketSlotConfiguration``
- ``YubiOTP/UpdateConfiguration``

### Configuration Options

- ``YubiOTP/SlotOptions``
- ``YubiOTP/KeyboardOptions``
- ``YubiOTP/TabOptions``
- ``YubiOTP/DelayOptions``

### Types

- ``YubiOTP/Slot``
- ``YubiOTP/Feature``
- ``YubiOTP/ConfigState``
- ``YubiOTP/NDEFType``
- ``YubiOTP/Status``
- ``YubiOTP/StatusStream``

### Errors

- ``YubiOTPSessionError``
