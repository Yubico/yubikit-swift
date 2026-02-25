# ``YubiKit/WebAuthn/PublicKeyCredential``

WebAuthn credential entity types for FIDO2 operations.

## Overview

PublicKeyCredential contains the entity types used in CTAP2 credential operations:

- ``UserEntity``: User account information (id, name, displayName)
- ``RPEntity``: Relying party information (id, name)
- ``Descriptor``: Credential identifier with type and optional transports

These types are used when creating credentials (MakeCredential) and authenticating (GetAssertion).

## Topics

### Credential Entities

- ``UserEntity``
- ``RPEntity``
- ``Descriptor``
