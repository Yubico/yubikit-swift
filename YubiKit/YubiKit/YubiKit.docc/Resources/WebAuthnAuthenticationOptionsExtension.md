# ``YubiKit/WebAuthn/Authentication/Options``

Options for authenticating with an existing passkey.

## Overview

`Options` is the input to ``WebAuthn/Client/getAssertion(_:authorization:)``.
Mirrors the W3C [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions).

An empty `allowCredentials` requests a discoverable-credential lookup; a
non-empty array narrows to specific credentials. If `rpId` is `nil`, the client
falls back to the host of its ``WebAuthn/Origin``.

```swift
let opts = WebAuthn.Authentication.Options(
    challenge: challenge,
    rpId: "example.com",
    allowCredentials: [.init(id: storedCredentialId)]
)
```

## Topics

### Creating Options

- ``init(challenge:rpId:allowCredentials:userVerification:timeout:extensions:)``

### Properties

- ``challenge``
- ``rpId``
- ``allowCredentials``
- ``userVerification``
- ``timeout``
- ``extensions``
