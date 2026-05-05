# ``YubiKit/WebAuthn/Extension``

WebAuthn-level extensions that wrap CTAP2 extensions for web compatibility.

## Overview

WebAuthn extensions provide a higher-level API that matches the W3C WebAuthn
specification. They wrap the underlying ``CTAP2/Extension``s and translate
between WebAuthn API semantics and CTAP2 protocol details — for example,
``PRF`` wraps the CTAP2 `hmac-secret` extension.

``WebAuthn/Client`` filters which extensions it will process via the
`allowedExtensions` parameter, a `Set<Identifier>`. Pass an array literal
(e.g. `[.prf, .credProps]`) or one of the static helpers
(``Swift/Set/standard``, ``Swift/Set/all``).

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
let response = try await client.makeCredential(opts, authorization: auth).value()
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
