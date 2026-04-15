# ``YubiKit/WebAuthn/Extension``

WebAuthn-level extensions that wrap CTAP2 extensions for web compatibility.

## Overview

WebAuthn extensions provide a higher-level API that matches the W3C WebAuthn specification.
They wrap the underlying CTAP2 extensions and handle the translation between WebAuthn
API semantics and CTAP2 protocol details.

For example, ``PRF`` wraps the CTAP2 `hmac-secret` extension, translating between
the WebAuthn PRF API (which uses salts as "eval" inputs) and the CTAP2 hmac-secret
protocol (which uses salt1/salt2 parameters).

## Topics

### PRF Extension

- ``PRF``

### PreviewSign Extension

- ``PreviewSign``
