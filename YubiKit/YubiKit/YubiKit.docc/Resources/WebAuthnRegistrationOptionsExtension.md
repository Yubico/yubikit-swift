# ``YubiKit/WebAuthn/Registration/Options``

Parameters for a credential registration request.

## Overview

`Options` is the input to ``WebAuthn/Client/makeCredential(_:authorization:)``. It
mirrors the W3C [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)
dictionary and is also exposed as the typealias
``WebAuthn/PublicKeyCredentialCreationOptions`` for code that mirrors the JavaScript API.

The most consequential fields are ``residentKey`` (whether the credential is
discoverable on the authenticator), ``userVerification`` (whether the ceremony
requires PIN or built-in UV), and ``pubKeyCredParams`` (the algorithms the relying
party accepts, ordered by preference). The relying party controls all three; the
client honours them subject to authenticator support.

Construct `Options` directly, or parse the relying party's JSON request with
``from(json:)`` — both paths produce the same value:

```swift
// Direct construction
let opts = WebAuthn.Registration.Options(
    challenge: challenge,
    rp: .init(id: "example.com", name: "Example"),
    user: .init(id: userId, name: "alice@example.com", displayName: "Alice"),
    residentKey: .preferred,
    pubKeyCredParams: [.es256, .edDSA, .rs256],
    extensions: .init(prf: .enable, credProps: true)
)

// From relying-party JSON
let opts = try WebAuthn.Registration.Options.from(json: rpJSON)
```

## Topics

### Creating Options

- ``init(challenge:rp:user:excludeCredentials:residentKey:userVerification:attestation:pubKeyCredParams:timeout:extensions:)``
- ``from(json:)``

### Properties

- ``challenge``
- ``rp``
- ``user``
- ``excludeCredentials``
- ``residentKey``
- ``userVerification``
- ``attestation``
- ``pubKeyCredParams``
- ``timeout``
- ``extensions``
