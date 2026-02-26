# ``YubiKit/CTAP2/GetInfo``

Types for the CTAP2 authenticatorGetInfo command.

## Overview

GetInfo contains types for the authenticatorGetInfo command response. The ``Response``
contains protocol versions, supported extensions, cryptographic algorithms, and option flags.

```swift
let info = try await session.getInfo()

// Check supported versions
if info.versions.contains(.fido2_1) {
    print("CTAP 2.1 supported")
}

// Check supported extensions
if info.extensions.contains(.hmacSecret) {
    print("hmac-secret extension available")
}

// Check authenticator options
if info.options.clientPin {
    print("PIN is configured")
}
```

## Topics

### Response Data

- ``Response``

### Authenticator Capabilities

- ``AuthenticatorVersion``
- ``Options``
- ``UVModality``
