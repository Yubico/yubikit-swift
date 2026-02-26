# ``YubiKit/CTAP2/Config``

Authenticator configuration operations (CTAP 2.1+).

## Overview

Config provides administrative operations to modify authenticator behavior. These operations
require a PIN/UV auth token with the ``CTAP2/ClientPin/Permission/authenticatorConfig`` permission.

```swift
let token = try await session.getPinUVToken(
    using: .pin("123456"),
    permissions: [.authenticatorConfig]
)
let config = try await session.config(token: token)

// Enable enterprise attestation
try await config.enableEnterpriseAttestation()

// Toggle always-require-UV setting
try await config.toggleAlwaysUV()

// Set minimum PIN length
try await config.setMinPINLength(newMinPINLength: 8, forceChangePin: true)
```

## Topics

### Feature Detection

- ``isSupported(by:)``

### Configuration Operations

- ``enableEnterpriseAttestation()``
- ``toggleAlwaysUV()``
- ``setMinPINLength(newMinPINLength:rpIDs:forceChangePin:)``

### Related Types

- ``Subcommand``
