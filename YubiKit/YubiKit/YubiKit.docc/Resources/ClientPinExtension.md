# ``YubiKit/CTAP2/ClientPin``

Types for CTAP2 PIN/UV (user verification) operations.

## Overview

ClientPin contains types for PIN/UV authentication. Use ``Method`` to specify PIN or
built-in UV, ``Permission`` to request capabilities for a token, and ``ProtocolVersion``
to select the cryptographic protocol.

```swift
// Get a PIN token for credential management
let token = try await session.getPinUVToken(
    using: .pin("123456"),
    permissions: [.credentialManagement]
)

// Set a new PIN (if none exists)
try await session.setPin("123456")

// Change existing PIN
try await session.changePin(from: "123456", to: "654321")
```

## Topics

### Protocol Versions

- ``ProtocolVersion``

### Authentication Methods

- ``Method``

### Permissions

- ``Permission``
