# ``YubiKit/WebAuthn/Authorization``

PIN and user-verification policy for a single WebAuthn ceremony.

## Overview

`Authorization` is supplied per ceremony to ``WebAuthn/Client/makeCredential(_:authorization:)``
and ``WebAuthn/Client/getAssertion(_:authorization:)``. It carries a `providePIN`
closure the SDK invokes when a PIN is needed, and a ``UVPolicy`` deciding
whether built-in user verification (e.g. fingerprint on a YubiKey Bio) is
attempted.

```swift
// Pre-supplied PIN — skips built-in UV.
let r = try await client.makeCredential(opts, authorization: .pin("1234")).value()

// Built-in UV only — the PIN closure is never invoked.
let r = try await client.makeCredential(opts, authorization: .uvOnly).value()

// Custom — bridge into a UI.
let auth = WebAuthn.Authorization(providePIN: {
    guard let pin = await viewModel.askForPIN() else { return .cancel }
    return .pin(pin)
}, uv: .preferred)
```

PIN attempts are one-shot: a wrong PIN throws
``WebAuthn/ClientError/pinRejected(retriesRemaining:source:)`` and the caller
re-invokes the ceremony with a fresh `Authorization`. Returning
``PINReply/cancel`` aborts with ``WebAuthn/ClientError/cancelled(source:)``.

## Topics

### Creating an Authorization

- ``init(providePIN:uv:)``
- ``pin(_:)``
- ``uvOnly``

### Properties

- ``providePIN``
- ``uv``

### Replies and Policy

- ``PINReply``
- ``UVPolicy``
