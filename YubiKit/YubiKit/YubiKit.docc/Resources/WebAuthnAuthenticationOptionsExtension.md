# ``YubiKit/WebAuthn/Authentication/Options``

Parameters for a credential assertion request.

## Overview

`Options` is the input to ``WebAuthn/Client/getAssertion(_:authorization:)``. It mirrors
the W3C [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions)
dictionary and is also exposed as the typealias
``WebAuthn/PublicKeyCredentialRequestOptions`` for code that mirrors the JavaScript API.

The shape of `allowCredentials` decides the ceremony's flavour. An empty array
requests a **discoverable-credential** lookup — the call resolves to an array
containing one ``WebAuthn/Authentication/Response`` per credential the
authenticator holds for the relying party. A non-empty array narrows the request
to specific credentials by identifier. If `rpId` is `nil`, the client falls back
to the host of its ``WebAuthn/Origin``.

Construct `Options` directly, or parse the relying party's JSON request with
``from(json:)`` — both paths produce the same value:

```swift
// Direct construction
let opts = WebAuthn.Authentication.Options(
    challenge: challenge,
    rpId: "example.com",
    allowCredentials: [.init(id: storedCredentialId)]
)

// From relying-party JSON
let opts = try WebAuthn.Authentication.Options.from(json: rpJSON)
```

## Topics

### Creating Options

- ``init(challenge:rpId:allowCredentials:userVerification:timeout:extensions:)``
- ``from(json:)``

### Properties

- ``challenge``
- ``rpId``
- ``allowCredentials``
- ``userVerification``
- ``timeout``
- ``extensions``
