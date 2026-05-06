# ``YubiKit/WebAuthn/Extension/PRF``

Pseudo-random function extension for deriving symmetric secrets bound to a credential.

## Overview

`PRF` lets a relying party derive deterministic symmetric secrets from a credential
— the same input produces the same output every time the user authenticates with
that credential. It's the [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
for credential-bound key derivation, built on the CTAP2 `hmac-secret` extension.
The SDK transforms each PRF input with `SHA-256("WebAuthn PRF\0" || input)` before
sending it to the authenticator — that domain separation is mandated by the spec.

In a high-level WebAuthn flow, configure `PRF` per ceremony via
``WebAuthn/Extension/RegistrationInputs/prf`` or
``WebAuthn/Extension/AuthenticationInputs/prf``; outputs come back on
`clientExtensionResults` of the corresponding `Response`. Registration enables
PRF on a credential, optionally deriving secrets at the same time on
authenticators that support hmac-secret-mc. Authentication evaluates the PRF at
one or more inputs and returns the derived bytes.

```swift
// Registration: enable PRF on the new credential
let regOpts = WebAuthn.Registration.Options(
    challenge: challenge,
    rp: .init(id: "example.com", name: "Example"),
    user: .init(id: userId, name: "alice@example.com"),
    extensions: .init(prf: .enable)
)
let registration = try await client.makeCredential(regOpts, authorization: auth).value

// Authentication: derive a secret bound to the credential
let authOpts = WebAuthn.Authentication.Options(
    challenge: challenge,
    rpId: "example.com",
    allowCredentials: [.init(id: storedCredentialId)],
    extensions: .init(prf: .eval(first: encryptionSeed))
)
let assertions = try await client.getAssertion(authOpts, authorization: auth).value
let derived = assertions.first?.clientExtensionResults.prf?.results.first
```

For multi-credential flows where each credential needs different inputs, populate
``Authentication/Input/evalByCredential`` with secrets keyed by credential id, with
``Authentication/Input/eval`` as the default for credentials not in the map.

`PRF` can also be used directly against a ``CTAP2/Session`` — bypassing
``WebAuthn/Client`` — for callers that drive CTAP2 themselves. Construct an
instance with ``init(session:)`` (or one of the secret-carrying initialisers),
then use ``makeCredential`` and ``getAssertion`` to build CTAP2 extension inputs
and parse outputs.

## Topics

### Registration

- ``Registration``
- ``WebAuthn/Extension/RegistrationInputs/prf``

### Authentication

- ``Authentication``
- ``WebAuthn/Extension/AuthenticationInputs/prf``

### Direct CTAP2 Use

- ``init(session:)``
- ``init(first:second:evalByCredential:session:)``
- ``init(evalByCredential:session:)``
- ``makeCredential``
- ``getAssertion``
- ``MakeCredentialOperations``
- ``GetAssertionOperations``

### Supporting Types

- ``Eval``
- ``Results``

### Salt Transformation

- ``salt(_:)``
