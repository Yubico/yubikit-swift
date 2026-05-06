# ``YubiKit/WebAuthn/Registration/Response``

Authenticator answer to a credential registration request.

## Overview

`Response` is the result of ``WebAuthn/Client/makeCredential(_:authorization:)``. It
carries the new credential's identifier, public key, attestation statement, and any
extension outputs the authenticator returned. The raw bytes
(``rawAttestationObject``, ``rawAuthenticatorData``) are kept alongside the parsed
forms so callers can ship them to the relying party verbatim.

The relying party verifies a registration by hashing `clientDataJSON`, running
the attestation statement format's verification procedure (`none`, `packed`,
`fido-u2f`, `tpm`, …), and applying its attestation policy. It then stores
``credentialId`` and ``publicKey`` against the user account for future assertions.
Use ``toJSON()`` to encode the response in the `PublicKeyCredential.toJSON()`
shape the relying party expects.

## Topics

### Credential

- ``credentialId``
- ``publicKey``
- ``transports``

### Attestation

- ``rawAttestationObject``
- ``attestationStatement``

### Authenticator Data

- ``rawAuthenticatorData``
- ``aaguid``
- ``signCount``

### Extensions

- ``clientExtensionResults``

### Serialization

- ``toJSON()``
