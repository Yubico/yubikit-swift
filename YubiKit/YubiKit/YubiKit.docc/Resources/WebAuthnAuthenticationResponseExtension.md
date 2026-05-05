# ``YubiKit/WebAuthn/Authentication/Response``

Authenticator response from a successful credential assertion.

## Overview

`Response` is the result of ``WebAuthn/Client/getAssertion(_:authorization:)``,
which returns an array containing one `Response` per matching credential. For
discoverable-credential requests this array can hold multiple entries — use
``user`` to drive a credential-selection UI.

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
