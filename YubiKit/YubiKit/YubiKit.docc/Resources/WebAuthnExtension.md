# ``YubiKit/WebAuthn``

A passkey client and the W3C Web Authentication data model, mediated by a YubiKey.

## Overview

The `WebAuthn` namespace provides a high-level passkey client (``Client``) that runs
[Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) ceremonies against a
YubiKey, plus the request and response types defined by the WebAuthn specification.

A WebAuthn ceremony involves three parties: the **authenticator** (a YubiKey), the
**client** (your app, via ``Client``), and the **relying party** (your server, which
verifies what the authenticator returns). The client is the communication path between
authenticator and relying party — and it verifies the relying party's identity against
the origin it's bound to, so it can refuse to sign for a fraudulent site.

There are two ceremonies. **Registration**
(``Client/makeCredential(_:authorization:)``) creates a new credential and supplies its
public key to the relying party for account association. **Authentication**
(``Client/getAssertion(_:authorization:)``) proves to the relying party that the
YubiKey is the one registered for the user. Both ceremonies follow the same mechanical
shape: the relying party supplies a challenge, the authenticator signs it together
with the relying-party identifier, and the signature goes back to the relying party
for verification.

The pieces fit together as: a connection carries CTAP2 traffic, a ``CTAP2/Session``
sits on top, and ``Client`` runs ceremonies on that session. Connections come in
three flavours that all work for WebAuthn: ``YubiKit/HIDFIDOConnection`` on macOS,
``YubiKit/NFCSmartCardConnection`` for tap-to-auth on iOS, and
``YubiKit/USBSmartCardConnection`` on either platform. Pick the one that matches
your platform and form factor.

```swift
// macOS — USB HID FIDO
let connection = try await HIDFIDOConnection()
// iOS — tap-to-auth over NFC:
// let connection = try await NFCSmartCardConnection()

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
).value

// Authenticate
let assertions = try await client.getAssertion(
    .init(challenge: challenge, rpId: "example.com"),
    authorization: .pin("1234")
).value
```

Most apps start with ``Client``. For lower-level CTAP2 access — raw `makeCredential` /
`getAssertion`, credential management, bio enrollment — use ``CTAP2/Session`` directly.

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
