# ``YubiKit``

Connect and run commands on the different applications on a YubiKey. The framework support connecting using NFC, Lightning and USB-C.

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
let connection = try await NFCSmartCardConnection.connection()
let session = try await OATHSession.session(withConnection: connection)
let codes = try await session.calculateCodes()
```

## Topics

### Preparing your project

- <doc:GettingStarted>

### Sample code

@Links(visualStyle: detailedGrid) {
    - <doc:OATHSampleCode>
    - <doc:PIVToolSampleCode>
}

### Creating a SmartCardConnection to a YubiKey

The implementations of the SmartCardConnection protocol handles the connection to the YubiKey and can be used to send
data in the form of a ``APDU`` to the YubiKey. In most cases it is adviced to use one of the supplied Sessions
(``OATHSession``, ``ManagementSession``) instead of sending raw APDUs to the YubiKey.


- ``SmartCardConnection``
- ``NFCSmartCardConnection``
- ``USBSmartCardConnection``
- ``LightningSmartCardConnection``
- ``WiredSmartCardConnection``

### Sending and receiving data

Use the default implementation of ``SmartCardConnection/send(apdu:)-7bmw4`` to send data to the YubiKey using the SmartCardConnection.
This will either return the full response data or throw a ``ResponseError``.

- ``APDU``

### Creating a Session

The implementations of the ``Session`` protocol provides an interface to the different applications on a YubiKey.
A Session is created by calling ``Session/session(withConnection:)`` providing the ``SmartCardConnection`` you want to use for
communication with the YubiKey.

- ``Session``
- ``OATHSession``
- ``ManagementSession``
- ``PIVSession``
- ``SecurityDomainSession``
