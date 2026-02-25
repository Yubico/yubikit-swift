# ``YubiKit/HIDFIDOConnection``

USB HID connection for FIDO2/CTAP communication (macOS only).

## Overview

HIDFIDOConnection establishes a FIDO2 connection to a YubiKey via USB HID. This is the
connection type used for CTAP2 operations on macOS, providing direct access to the
YubiKey's FIDO authenticator.

```swift
let connection = try await HIDFIDOConnection()
let session = try await CTAP2.Session.makeSession(connection: connection)

// Get authenticator info
let info = try await session.getInfo()
print("AAGUID: \(info.aaguid)")

// Create a credential
let token = try await session.getPinUVToken(using: .pin("123456"), permissions: [.makeCredential])
let response = try await session.makeCredential(parameters: params, token: token).value
```

> Note: This connection type is only available on macOS. On iOS, use ``NFCSmartCardConnection``
> for CTAP2 operations.

## Topics

### Creating a Connection

- ``init()``
- ``makeConnection()``

### Connection Lifecycle

- ``close(error:)``
- ``waitUntilClosed()``

### Packet Communication

- ``mtu``
- ``send(_:)``
- ``receive()``

### Errors

- ``FIDOConnectionError``
