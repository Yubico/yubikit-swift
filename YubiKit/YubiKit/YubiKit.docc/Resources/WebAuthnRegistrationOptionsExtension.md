# ``YubiKit/WebAuthn/Registration/Options``

Options for registering a new passkey.

## Overview

`Options` is the input to ``WebAuthn/Client/makeCredential(_:authorization:)``.
Mirrors the W3C [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions).

```swift
let opts = WebAuthn.Registration.Options(
    challenge: challenge,
    rp: .init(id: "example.com", name: "Example"),
    user: .init(id: userId, name: "alice@example.com", displayName: "Alice"),
    residentKey: .preferred,
    pubKeyCredParams: [.es256, .edDSA, .rs256],
    extensions: .init(prf: .enable, credProps: true)
)
```

## Topics

### Creating Options

- ``init(challenge:rp:user:excludeCredentials:residentKey:userVerification:attestation:pubKeyCredParams:timeout:extensions:)``

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
