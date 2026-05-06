# ``YubiKit/CTAP2/Extension``

CTAP2 protocol extensions for additional authenticator functionality.

## Overview

CTAP2 extensions provide optional features like secret derivation (hmac-secret),
credential protection levels (credProtect), and large blob storage (largeBlobKey).
Each extension provides typed inputs for ``CTAP2/MakeCredential`` and/or ``CTAP2/GetAssertion``.

```swift
// Use hmac-secret to derive a secret during authentication
let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
let salt = Data(repeating: 0x42, count: 32)

let params = CTAP2.GetAssertion.Parameters(
    rpId: "example.com",
    clientDataHash: hash,
    extensions: [try hmacSecret.getAssertion.input(salt1: salt)]
)
let response = try await session.getAssertion(parameters: params, token: token).value
let secret = try hmacSecret.getAssertion.output(from: response)
```

## Topics

### Extension Identifiers

- ``Identifier``

### Input Types

- ``MakeCredential``
- ``GetAssertion``

### Available Extensions

- ``HmacSecret``
- ``CredProtect``
- ``CredBlob``
- ``LargeBlobKey``
- ``MinPinLength``
- ``ThirdPartyPayment``
- ``PreviewSign``
