# ``YubiKit/WebAuthn/Authentication/Response``

Authenticator answer to a credential assertion request.

## Overview

`Response` is the result of ``WebAuthn/Client/getAssertion(_:authorization:)``, which
returns an array containing one `Response` per matching credential. For
discoverable-credential requests (empty `allowCredentials`) the array can hold
multiple entries — use ``user`` to drive a credential-selection UI. For allow-list
requests, expect one entry per allow-list credential the authenticator actually
holds — typically one, but it can be more if multiple allow-list entries match.

The relying party verifies an assertion by checking ``signature`` over the
concatenation of ``rawAuthenticatorData`` and the SHA-256 of `clientDataJSON`, using
the public key it stored at registration time. Use ``toJSON()`` to encode the
response in the `PublicKeyCredential.toJSON()` shape the relying party expects, and
POST it.

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

### Serialization

- ``toJSON()``
