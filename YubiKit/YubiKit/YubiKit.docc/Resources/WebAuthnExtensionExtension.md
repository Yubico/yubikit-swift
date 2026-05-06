# ``YubiKit/WebAuthn/Extension``

WebAuthn-level extensions that wrap CTAP2 extensions for web compatibility.

## Overview

WebAuthn extensions provide a higher-level API that matches the W3C WebAuthn
specification. They are built on the underlying ``CTAP2/Extension``s and adapt
them to WebAuthn API semantics. For example, ``PRF`` is built on the CTAP2
`hmac-secret` extension but adds input hashing for domain separation and
exposes a single UV-scoped PRF rather than `hmac-secret`'s UV/non-UV pair.

``WebAuthn/Client`` filters which extensions it will process via the
`allowedExtensions` parameter, a `Set<Identifier>`. Pass an array literal (e.g.
`[.prf, .credProps]`) or one of the static helpers (``Swift/Set/standard``,
``Swift/Set/all``). Extensions are configured per ceremony on
``WebAuthn/Registration/Options/extensions`` or
``WebAuthn/Authentication/Options/extensions``, and outputs come back on
`clientExtensionResults` of the corresponding `Response`.

```swift
let opts = WebAuthn.Registration.Options(
    challenge: challenge,
    rp: .init(id: "example.com", name: "Example"),
    user: .init(id: userId, name: "alice@example.com"),
    extensions: .init(
        prf: .enable,
        credProtect: .enforced(.userVerificationRequired),
        credProps: true
    )
)
let response = try await client.makeCredential(opts, authorization: auth).value
```

## Topics

### Selecting Extensions

- ``Identifier``

### Supported Extensions

- ``PRF``
- ``CredProtect``
- ``CredBlob``
- ``CredProps``
- ``LargeBlob``
- ``MinPinLength``
- ``ThirdPartyPayment``
- ``PreviewSign``

### Aggregate Inputs and Outputs

- ``RegistrationInputs``
- ``RegistrationOutputs``
- ``AuthenticationInputs``
- ``AuthenticationOutputs``
