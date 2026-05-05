# ``YubiKit/WebAuthn/Authentication/Response``

Authenticator response from a successful credential assertion.

## Overview

`Response` is the result of ``WebAuthn/Client/getAssertion(_:authorization:)``.
For discoverable-credential requests, the SDK returns one `Response` per
matching credential — use ``user`` to drive a credential-selection UI.

## Topics

### Credential

- ``credentialId``
- ``user``

### Signed Data

- ``rawAuthenticatorData``
- ``signature``
- ``signCount``

### Extensions

- ``clientExtensionResults``
