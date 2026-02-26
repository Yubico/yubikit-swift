# ``YubiKit/WebAuthn/AttestationStatement``

Attestation statement formats from credential creation.

## Overview

AttestationStatement represents the cryptographic proof that a credential was created
by a genuine authenticator. Different authenticators use different attestation formats:

- ``Packed``: Standard FIDO2 packed attestation (most YubiKeys)
- ``FIDOU2F``: Legacy U2F attestation format
- ``Apple``: Apple attestation format

Access the attestation statement through ``WebAuthn/AttestationObject/statement``.

## Topics

### Attestation Formats

- ``Packed``
- ``FIDOU2F``
- ``Apple``
