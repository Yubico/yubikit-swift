# ``YubiKit/YubiOTP/Session``

Session for the Yubico OTP application on the YubiKey.

## Overview

YubiOTP.Session programs the two OTP slots of the YubiKey for Yubico OTP, OATH-HOTP, static
passwords, or HMAC-SHA1 challenge-response. For keyboard output, a short touch triggers slot 1 and
a long touch triggers slot 2. These slots are separate from the credentials of ``OATHSession``.

On macOS, use ``HIDOTPConnection`` to configure a slot and calculate a challenge-response:

```swift
let connection = try await HIDOTPConnection()
let session = try await YubiOTP.Session.makeSession(connection: connection)

// Program slot 2 for HMAC-SHA1 challenge-response
try await session.putConfiguration(.hmacSHA1(key: secret), in: .two)

// Calculate a response
let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
```

### Transports

Create a session with an ``OTPConnection`` on macOS or a ``SmartCardConnection`` on macOS and
iOS. The available operations depend on the connection:

| Operation | OTP keyboard HID (macOS) | USB or Lightning SmartCard | NFC |
| --- | --- | --- | --- |
| Slot programming | Yes | Yes | Yes |
| HMAC-SHA1 challenge-response | Yes | No | Only without touch |
| Touch progress and cancellation | Yes | No | No |

For slots configured with `requireTouch: true`, iterate ``YubiOTP/StatusStream`` to prompt for
touch and offer cancellation using the closure supplied by ``YubiOTP/Status/waitingForUser(cancel:)``.

### Access Codes

An access code protects the configuration of a slot. It does not protect the output of the slot.
The YubiKey cannot return the access code, so supply `currentAccessCode` for each change to a
protected slot. A write keeps the current code by default. Pass `accessCode: .set(newCode)` to
replace it, or `accessCode: .remove` to remove it.

### NFC Output

Use ``setNDEFConfiguration(in:uri:currentAccessCode:)`` to choose the URI prefix for a slot's NFC
output. The YubiKey appends the generated OTP to this prefix. It defaults to
``YubiOTP/defaultNDEFURI``; you can supply a custom URL:

```swift
// Use the OTP from an already configured slot
try await session.setNDEFConfiguration(in: .one, uri: URL(string: "https://example.com/otp?code=")!)
```

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
- ``setNDEFConfiguration(in:uri:currentAccessCode:)``

### Challenge-Response

- ``calculateHMACSHA1(challenge:in:)``

### Slot Configurations

- ``YubiOTP/SlotConfiguration``
- ``YubiOTP/SlotConfiguration/hmacSHA1(key:requireTouch:messageUnder64Bytes:options:)``
- ``YubiOTP/SlotConfiguration/yubicoOTP(publicID:privateID:key:tabs:delays:sendReference:keyboard:options:)``
- ``YubiOTP/SlotConfiguration/hotp(key:digits:tokenID:tokenIDEncoding:initialCounter:keyboard:options:)``
- ``YubiOTP/SlotConfiguration/staticPassword(scanCodes:keyboard:options:)``
- ``YubiOTP/SlotConfiguration/staticTicket(fixed:uid:key:shortTicket:upperCase:digit:special:manualUpdate:keyboard:options:)``
- ``YubiOTP/SlotUpdate``

### Configuration Options

- ``YubiOTP/SlotOptions``
- ``YubiOTP/KeyboardOptions``
- ``YubiOTP/TabOptions``
- ``YubiOTP/DelayOptions``
- ``YubiOTP/SlotConfiguration/Digits``
- ``YubiOTP/SlotConfiguration/TokenIDEncoding``
- ``YubiOTP/KeyboardOptions/Pacing``
- ``YubiOTP/AccessCodeChange``

### Types

- ``YubiOTP/Slot``
- ``YubiOTP/Feature``
- ``YubiOTP/ConfigState``
- ``YubiOTP/Status``
- ``YubiOTP/StatusStream``

### Errors

- ``YubiOTP/SessionError``
