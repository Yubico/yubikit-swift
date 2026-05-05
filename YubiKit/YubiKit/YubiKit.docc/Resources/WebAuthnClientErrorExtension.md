# ``YubiKit/WebAuthn/ClientError``

Errors thrown from WebAuthn client ceremonies.

## Overview

`ClientError` reports failures during ``WebAuthn/Client/makeCredential(_:authorization:)``
and ``WebAuthn/Client/getAssertion(_:authorization:)``. CTAP2 errors raised by
the authenticator are mapped onto the typed cases below; anything unmapped
surfaces as ``ctapError(_:source:)``.

`pinRejected`, `uvRejected`, `uvBlocked`, and `pinTokenExpired` are recoverable
— re-invoke the ceremony with a fresh ``WebAuthn/Authorization``.

## Topics

### PIN / UV

- ``pinRejected(retriesRemaining:source:)``
- ``uvRejected(retriesRemaining:source:)``
- ``uvBlocked(source:)``
- ``pinBlocked(source:)``
- ``pinAuthBlocked(source:)``
- ``pinNotSet(source:)``
- ``pinComplexity(source:)``
- ``forcePinChange(source:)``
- ``pinTokenExpired(source:)``

### Request

- ``invalidRequest(_:source:)``
- ``unsupportedAlgorithm(source:)``
- ``credentialExcluded(source:)``
- ``noCredentials(source:)``
- ``notSupported(_:source:)``
- ``storageFull(source:)``

### Cancellation and Transport

- ``cancelled(source:)``
- ``timeout(source:)``
- ``authenticatorNotAvailable(source:)``

### Catch-alls

- ``ctapError(_:source:)``
- ``internalError(_:source:)``
