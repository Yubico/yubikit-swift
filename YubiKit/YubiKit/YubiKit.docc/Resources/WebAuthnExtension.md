# ``YubiKit/WebAuthn``

Namespace for the WebAuthn client and the W3C Web Authentication data model.

## Overview

The `WebAuthn` namespace provides a high-level passkey client (``Client``) backed
by a YubiKey via CTAP2, plus the request/response types defined by the
[Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) specification.

For most apps, ``Client`` is the entry point. For lower-level CTAP2 access (raw
`makeCredential` / `getAssertion`, credential management, bio enrollment), use
``CTAP2/Session`` directly.

```swift
let connection = try await HIDFIDOConnection()
let session = try await CTAP2.Session.makeSession(connection: connection)
let client = WebAuthn.Client(
    session: session,
    origin: try .init("https://example.com"),
    isPublicSuffix: { publicSuffixList.contains($0) }
)

// Register a new passkey
let registration = try await client.makeCredential(
    .init(
        challenge: challenge,
        rp: .init(id: "example.com", name: "Example"),
        user: .init(id: userId, name: "alice@example.com")
    ),
    authorization: .pin("1234")
).value()

// Authenticate
let assertions = try await client.getAssertion(
    .init(challenge: challenge, rpId: "example.com"),
    authorization: .pin("1234")
).value()
```

## Topics

### Client

- ``Client``
- ``Authorization``
- ``Origin``
- ``ClientError``
- ``ClientData``
- ``PublicSuffixChecker``

### Registration (makeCredential)

- ``Registration``
- ``PublicKeyCredentialCreationOptions``

### Authentication (getAssertion)

- ``Authentication``
- ``PublicKeyCredentialRequestOptions``

### Status Reporting

- ``StatusStream``
- ``Status``

### Relying Party and User Entities

- ``RelyingParty``
- ``User``
- ``CredentialDescriptor``
- ``Transport``

### Ceremony Preferences

- ``ResidentKeyPreference``
- ``UserVerificationPreference``
- ``AttestationPreference``

### Authenticator Data

- ``AuthenticatorData``
- ``AttestedCredentialData``
- ``AAGUID``

### Attestation

- ``AttestationObject``
- ``AttestationStatement``
- ``AttestationFormat``

### Extensions

- ``Extension``
