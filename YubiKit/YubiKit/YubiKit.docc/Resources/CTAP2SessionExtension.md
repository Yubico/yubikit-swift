# ``YubiKit/CTAP2/Session``

Session for FIDO2/CTAP2 operations on a YubiKey.

## Overview

CTAP2.Session provides access to FIDO2 functionality including credential
registration (makeCredential), authentication (getAssertion), PIN management, and
optional features like credential management and biometric enrollment.

Create a session from any ``FIDOConnection`` or ``SmartCardConnection``:

```swift
// USB HID connection (macOS)
let hidConnection = try await HIDFIDOConnection()
let session = try await CTAP2.Session.makeSession(connection: hidConnection)

// NFC connection (iOS)
let nfcConnection = try await NFCSmartCardConnection()
let session = try await CTAP2.Session.makeSession(connection: nfcConnection)

// Get authenticator info
let info = try await session.getInfo()

// Get a PIN token for authenticated operations
let token = try await session.getPinUVToken(
    using: .pin("123456"),
    permissions: [.makeCredential, .getAssertion],
    rpId: "example.com"
)

// Create a credential
let response = try await session.makeCredential(parameters: params, token: token).value
```

## Topics

### Authenticator Information

- ``getInfo()``
- ``selection()``
- ``reset()``

### Credential Operations

- ``makeCredential(parameters:token:)``
- ``getAssertion(parameters:token:)``
- ``getAssertions(parameters:token:)``
- ``getNextAssertion()``

### PIN/UV Authentication

- ``getPinUVToken(using:permissions:rpId:protocol:)``
- ``setPin(_:protocol:)``
- ``changePin(from:to:protocol:)``
- ``getPinRetries(protocol:)``
- ``getUVRetries(protocol:)``

### Feature Accessors

- ``config(token:)``
- ``credentialManagement(token:)``
- ``bioEnrollment(token:)``

### Large Blobs

- ``supportsLargeBlobs()``
- ``getBlob(key:)``
- ``putBlob(key:data:token:)``
- ``deleteBlob(key:token:)``

### Related Types

- ``CTAP2/Token``
- ``CTAP2/Config``
- ``CTAP2/CredentialManagement``
- ``CTAP2/BioEnrollment``
- ``CTAP2/GetInfo``
- ``CTAP2/MakeCredential``
- ``CTAP2/GetAssertion``
- ``CTAP2/StatusStream``

### Extensions

- ``CTAP2/Extension``

### Errors

- ``CTAP2/SessionError``
