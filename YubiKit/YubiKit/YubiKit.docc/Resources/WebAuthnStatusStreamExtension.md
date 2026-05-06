# ``YubiKit/WebAuthn/StatusStream``

Async sequence yielding progress updates during a WebAuthn ceremony.

## Overview

``WebAuthn/Client/makeCredential(_:authorization:)`` and
``WebAuthn/Client/getAssertion(_:authorization:)`` return a `StatusStream` that
yields ``WebAuthn/Status`` values as the ceremony progresses. PIN entry and UV
decisions are handled out-of-band via ``WebAuthn/Authorization`` — they do *not*
appear on this stream.

For non-UI callers, drain with ``value()`` and ignore progress. For UI integration,
iterate to drive cancel buttons, biometric prompts, or a spinner. The stream
deduplicates consecutive identical
`.processing` / `.waitingForUser` / `.waitingForUserVerification` events, so each
emission reflects a real state change.

```swift
for try await status in await client.makeCredential(opts, authorization: auth) {
    switch status {
    case .processing:
        showSpinner()
    case .waitingForUser(let cancel):
        showTouchPrompt(onCancel: { Task { await cancel() } })
    case .waitingForUserVerification(let cancel, let fallbackToPIN):
        showBiometricPrompt(
            onCancel: { Task { await cancel() } },
            onFallbackToPIN: fallbackToPIN.map { fallback in { Task { await fallback() } } }
        )
    case .finished(let response):
        return response
    }
}
```

## Topics

### Consuming the Stream

- ``value()``
- ``makeAsyncIterator()``

### Status Values

- ``WebAuthn/Status``
