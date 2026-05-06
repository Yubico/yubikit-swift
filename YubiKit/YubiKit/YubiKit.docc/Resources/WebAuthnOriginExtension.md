# ``YubiKit/WebAuthn/Origin``

A validated WebAuthn origin (`scheme://host[:port]`).

## Overview

`Origin` is the secure origin that ``WebAuthn/Client`` is bound to. It enforces the
W3C secure-context rule: only `https://` is accepted, with an exception for
`http://localhost` (and `*.localhost`) for local development. Path, query, and
fragment are stripped.

The origin is used for relying-party identifier validation (combined with the
``WebAuthn/PublicSuffixChecker`` supplied to ``WebAuthn/Client``) and is serialized
into the `clientDataJSON` of every ceremony. See
[RFC 6454](https://tools.ietf.org/html/rfc6454) for the origin concept and
[W3C Secure Contexts](https://w3c.github.io/webappsec-secure-contexts/) for the
secure-context rule.

## Topics

### Creating an Origin

- ``init(_:)-(String)``
- ``init(_:)-(URL)``

### Properties

- ``stringValue``
- ``host``

### Errors

- ``Error``
