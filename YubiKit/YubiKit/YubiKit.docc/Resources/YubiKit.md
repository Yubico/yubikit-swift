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
let connection = try await NFCSmartCardConnection.makeConnection()
let session = try await OATHSession.makeSession(connection: connection)
let codes = try await session.calculateCredentialCodes()
```

> Warning: This SDK does not perform zeroization of sensitive data in memory. Cryptographic keys, PIN tokens,
> and other secrets are not securely erased when no longer in use. This is currently out of scope but may be
> addressed in a future release.

## Topics

### Preparing your project

- <doc:GettingStarted>

### Sample code

@Links(visualStyle: detailedGrid) {
    - <doc:OATHSampleCode>
    - <doc:PIVToolSampleCode>
    - <doc:WebAuthnInterceptorSampleCode>
}

### Creating a SmartCardConnection to a YubiKey

The implementations of the SmartCardConnection protocol handle the connection to the YubiKey and can be used to send
data to the YubiKey. In most cases it is advised to use one of the supplied Sessions
(``OATHSession``, ``Management/Session``) instead of sending raw data to the YubiKey.


- ``SmartCardConnection``
- ``NFCSmartCardConnection``
- ``USBSmartCardConnection``
- ``LightningSmartCardConnection``
- ``WiredSmartCardConnection``

> Note: `NFCSmartCardConnection` and `LightningSmartCardConnection` are available on iOS only.

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
