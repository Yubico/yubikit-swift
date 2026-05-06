# ``YubiKit/WebAuthn/Client``

`Client` is a high-level passkey client that runs WebAuthn ceremonies against a YubiKey.

## Overview

`Client` is the entry point for WebAuthn in this SDK. It wraps a ``CTAP2/Session``
and translates W3C WebAuthn requests into CTAP2 protocol exchanges — building the
`clientDataJSON`, validating the relying-party identifier against the configured
``WebAuthn/Origin``, selecting between PIN and built-in user verification, and
processing extensions before the request reaches the authenticator.

Use `Client` for any app that runs passkey ceremonies. Reach for ``CTAP2/Session``
directly only when you need lower-level access — raw `makeCredential` /
`getAssertion`, credential management, or bio enrollment.

`Client` is an actor; a client's lifetime is bound to the underlying ``CTAP2/Session``.

The constructor takes four parameters that shape every ceremony:

- `origin` — the secure origin the client is bound to. ``WebAuthn/Origin`` enforces
  the W3C secure-context rule; the client refuses to sign for relying parties whose
  identifier doesn't match.
- `isPublicSuffix` — a closure into a Public Suffix List, used to validate that
  the relying-party identifier is a registrable suffix of the origin's effective
  domain.
- `enterpriseRpIds` — relying-party identifiers allowed to receive
  platform-managed enterprise attestation. When the request specifies
  ``WebAuthn/AttestationPreference/enterprise``, the client escalates to level 2
  (platform-managed) for RPs in this set, and uses level 1 (vendor-facilitated)
  otherwise.
- `allowedExtensions` — the set of WebAuthn extensions the client will process.
  Anything the relying party requests outside this set is dropped before reaching
  the authenticator. Defaults to ``WebAuthn/Extension``'s standard set.

PIN and user verification are supplied per ceremony via ``WebAuthn/Authorization``,
out-of-band from the ceremony stream. Both ceremony methods return a
``WebAuthn/StatusStream`` — drain it with `value()` for non-UI callers, or iterate
to drive cancel buttons and biometric prompts.

```swift
let client = WebAuthn.Client(
    session: session,
    origin: try .init("https://example.com"),
    isPublicSuffix: { publicSuffixList.contains($0) }
)

for try await status in await client.makeCredential(opts, authorization: .pin("1234")) {
    switch status {
    case .processing:
        showSpinner()
    case .waitingForUser(let cancel):
        showTouchPrompt(onCancel: { Task { await cancel() } })
    case .waitingForUserVerification(let cancel, _):
        showBiometricPrompt(onCancel: { Task { await cancel() } })
    case .finished(let response):
        return response
    }
}
```

The `clientData:` overloads accept a pre-built ``WebAuthn/ClientData`` instead of
building one from `origin` + challenge. Use them in iOS Credential Provider /
AutoFill flows, where the system supplies a precomputed `clientDataHash` rather
than the full `clientDataJSON`.

## Topics

### Creating a Client

- ``init(session:origin:enterpriseRpIds:allowedExtensions:isPublicSuffix:)``

### Registration

- ``makeCredential(_:authorization:)``
- ``makeCredential(_:clientData:authorization:)``

### Authentication

- ``getAssertion(_:authorization:)``
- ``getAssertion(_:clientData:authorization:)``

### Configuration

- ``WebAuthn/Authorization``
- ``WebAuthn/Origin``
- ``WebAuthn/PublicSuffixChecker``
- ``WebAuthn/ClientData``

### Status Reporting

- ``WebAuthn/StatusStream``

### Errors

- ``WebAuthn/ClientError``
