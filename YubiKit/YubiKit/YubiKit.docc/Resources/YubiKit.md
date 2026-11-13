# ``YubiKit``

Connect and run commands on the different applications on a YubiKey. The framework support connecting using NFC, Lightning and USB.

@Metadata {
    @PageImage(purpose: icon, 
               source: "documentation-header", 
               alt: "YubiKeys in a row")
    @PageColor(green)
    @Available(macOS, introduced: "13.0")
    @Available(iOS, introduced: "16.0")
}

## Overview

The YubiKit Swift SDK provides a modern async/await version of the YubiKit framework, making it easy to integrate
in Swift and SwiftUI based applications. The async/await syntax provides an easy to read and powerful way of
creating connections and sending commands to the different applications on the YubiKey.

```swift
let connection = try await NFCSmartCardConnection()
let session = try await OATHSession.makeSession(connection: connection)
let codes = try await session.calculateCredentialCodes()
```

> Warning: This SDK does not perform zeroization of sensitive data in memory. Cryptographic keys, PIN tokens,
> and other secrets are not securely erased when no longer in use. This is currently out of scope but may be
> addressed in a future release.

## Task cancellation

The SDK respects cancellation before new work and at cancellable waits, while letting started
exchanges and required cleanup finish.

Cancellable waits include discovering and attaching to a YubiKey, consuming status streams, and
waiting for touch. Session commands check cancellation before starting a new exchange over smart
card or HID connections, including NFC and Lightning.

A command already sent to the YubiKey may finish. Cancellation does not undo device changes, and a
completed command can still return a result. Operations with several commands can stop between them.

Cancelling a status-stream consumer can return before its command finishes cleanup. A later command
on the same CTAP2 session waits for that cleanup. Reuse the session, or close the connection before
opening a new connection and session. Concurrent sessions on one connection are not supported.

Low-level connection methods send raw APDUs or HID reports. Callers using them directly must manage
cancellation between complete exchanges. ``Connection/waitUntilClosed()`` waits for an actual close,
even if its task is cancelled.

## Topics

### Preparing your project

- <doc:GettingStarted>
- <doc:LoggingGuide>
- ``Logs``

### Sample code

@Links(visualStyle: detailedGrid) {
    - <doc:OATHSampleCode>
    - <doc:PIVToolSampleCode>
    - <doc:WebAuthnInterceptorSampleCode>
}

### Creating a SmartCardConnection to a YubiKey

The implementations of the ``SmartCardConnection`` protocol handle the connection to the YubiKey and can be used to send
data to the YubiKey. In most cases it is advised to use one of the supplied Sessions
(``OATHSession``, ``Management/Session``) instead of sending raw data to the YubiKey.


- ``SmartCardConnection``
- ``NFCSmartCardConnection``
- ``USBSmartCardConnection``
- ``LightningSmartCardConnection``
- ``WiredSmartCardConnection``

> Note: `NFCSmartCardConnection` and `LightningSmartCardConnection` are available on iOS only.

### Creating a FIDO connection to a YubiKey

The implementations of the ``FIDOConnection`` protocol handle FIDO2/CTAP2 communication with the YubiKey over USB HID.

- ``FIDOConnection``
- ``HIDFIDOConnection``

### Creating an OTP connection to a YubiKey

The implementations of the ``OTPConnection`` protocol handle Yubico OTP communication with the YubiKey over
the keyboard HID interface. ``YubiOTP/Session`` also works over a ``SmartCardConnection``, which is the only
option on iOS and over NFC.

- ``OTPConnection``
- ``HIDOTPConnection``

> Note: `HIDOTPConnection` is available on macOS only.

### Reading device information

Create a ``YubiKey`` snapshot before creating application sessions. Discovery reads the connection once;
accessing the snapshot's name and metadata does not communicate with the device.

```swift
let key = try await YubiKey(connection: connection)
let name = key.deviceName
let info = key.deviceInfo
```

- ``YubiKey``
- ``DeviceInfo``

### Sending and receiving data

Use ``SmartCardConnection/send(data:)`` to send raw data to the YubiKey using the SmartCardConnection.
For most use cases, it's recommended to use one of the provided Sessions instead of sending raw data.

### Creating a Session

The implementations of the ``Session`` protocol provides an interface to the different applications on a YubiKey.
A Session is created by calling the `makeSession(connection:)` method on the session type, providing the
``SmartCardConnection`` you want to use for communication with the YubiKey.

- ``Session``
- ``OATHSession``
- ``Management/Session``
- ``PIVSession``
- ``SecurityDomainSession``

### Yubico OTP Session

The ``YubiOTP/Session`` programs and challenges the YubiKey's two OTP slots. It can be created using either
an ``OTPConnection`` (``HIDOTPConnection`` on macOS) or a ``SmartCardConnection``.

- ``YubiOTP``
- ``YubiOTP/Session``

### FIDO2 / CTAP2 Session

The ``CTAP2/Session`` provides access to the FIDO2/CTAP2 functionality of a YubiKey. It can be created using
either a ``FIDOConnection`` (such as ``HIDFIDOConnection`` for USB HID) or a ``SmartCardConnection``
(such as ``NFCSmartCardConnection`` for NFC).

- ``CTAP2/Session``

### WebAuthn Client

The ``WebAuthn/Client`` is a high-level passkey client built on top of ``CTAP2/Session``. It implements
the W3C Web Authentication ceremonies (registration and authentication), handles client-data construction,
RP-ID validation, PIN/UV selection, and extension processing.

- ``WebAuthn``
- ``WebAuthn/Client``
