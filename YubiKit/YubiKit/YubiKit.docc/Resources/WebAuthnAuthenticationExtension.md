# ``YubiKit/WebAuthn/Authentication``

Namespace for credential authentication (`getAssertion`) request and response types.

## Overview

`Authentication` collects the request (``Options``) and response (``Response``)
types used by ``WebAuthn/Client/getAssertion(_:authorization:)``. ``Options``
is also exposed as the typealias ``PublicKeyCredentialRequestOptions`` for
code that mirrors the JavaScript API. A discoverable-credential request
(empty `allowCredentials`) returns one ``Response`` per matching credential.

## Topics

### Request

- ``Options``

### Response

- ``Response``
