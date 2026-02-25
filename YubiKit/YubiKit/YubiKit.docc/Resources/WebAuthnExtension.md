# ``YubiKit/WebAuthn``

WebAuthn data types for FIDO2 credential responses and attestation.

## Overview

The WebAuthn namespace contains types that represent CTAP2 response data, matching
the W3C Web Authentication specification structures.

- ``AuthenticatorData``: Parsed authenticator data including RP ID hash, flags, and counter
- ``AttestedCredentialData``: Credential ID and public key from registration
- ``AttestationObject``: Full attestation with format, statement, and authenticator data
- ``PublicKeyCredential``: Entity types for users, relying parties, and credential descriptors

## Topics

### Authenticator Data

- ``AuthenticatorData``
- ``AttestedCredentialData``

### Attestation

- ``AttestationObject``
- ``AttestationStatement``
- ``AttestationFormat``

### Credential Entities

- ``PublicKeyCredential``

### Extensions

- ``Extension``
