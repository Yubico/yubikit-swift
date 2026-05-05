# ``YubiKit/WebAuthn/Client``

High-level client for passkey registration and authentication backed by a YubiKey.

## Overview

`Client` is the top-level entry point for WebAuthn ceremonies. It wraps a
``CTAP2/Session`` and translates W3C WebAuthn requests into the underlying
CTAP2 protocol, handling client-data construction, RP-ID validation, PIN/UV
selection, and extension processing.

```swift
let connection = try await HIDFIDOConnection()
let session = try await CTAP2.Session.makeSession(connection: connection)

let client = WebAuthn.Client(
    session: session,
    origin: try .init("https://example.com"),
    isPublicSuffix: { publicSuffixList.contains($0) }
)

let response = try await client.makeCredential(opts, authorization: .pin("1234")).value()
```

PIN/UV is supplied per ceremony via ``WebAuthn/Authorization``. Both ceremony
methods return a ``WebAuthn/StatusStream`` — drain with `value()` for non-UI
callers, or iterate to drive cancel buttons and biometric prompts.

`allowedExtensions` filters which WebAuthn extensions the client will process —
anything the RP requests outside this set is silently dropped before reaching
the authenticator. Defaults to ``WebAuthn/Extension``'s standard set (every
extension except `thirdPartyPayment` and `previewSign`).

## Topics

### Creating a Client

- ``init(session:origin:enterpriseRpIds:allowedExtensions:isPublicSuffix:)``

### Registration

- ``makeCredential(_:authorization:)``
- ``makeCredential(_:clientData:authorization:)``

### Authentication

- ``getAssertion(_:authorization:)``
- ``getAssertion(_:clientData:authorization:)``

### Related Types

- ``WebAuthn/Authorization``
- ``WebAuthn/Origin``
- ``WebAuthn/StatusStream``
- ``WebAuthn/ClientData``
- ``WebAuthn/PublicSuffixChecker``

### Errors

- ``WebAuthn/ClientError``
