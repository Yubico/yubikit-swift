# ``YubiKit/WebAuthn/Registration/Response``

Authenticator response from a successful credential registration.

## Overview

`Response` is the result of ``WebAuthn/Client/makeCredential(_:authorization:)``.
It carries the new credential's identifier, public key, attestation, and any
extension outputs the authenticator returned. The raw bytes (``rawAttestationObject``,
``rawAuthenticatorData``) are kept alongside the parsed forms so callers can
ship them to a relying party verbatim.

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
