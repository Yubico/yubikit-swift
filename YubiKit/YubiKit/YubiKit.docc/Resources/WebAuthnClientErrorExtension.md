# ``YubiKit/WebAuthn/ClientError``

Errors thrown from WebAuthn client ceremonies.

## Overview

`ClientError` reports failures from
``WebAuthn/Client/makeCredential(_:authorization:)`` and
``WebAuthn/Client/getAssertion(_:authorization:)``. CTAP2 errors raised by the
authenticator are mapped onto the typed cases below; anything unmapped surfaces as
``ctapError(_:source:)``.

Recoverability is graded:

- ``pinRejected(retriesRemaining:source:)``, ``uvRejected(retriesRemaining:source:)``,
  and ``pinTokenExpired(source:)`` — re-invoke the ceremony with a fresh
  ``WebAuthn/Authorization``.
- ``uvBlocked(source:)`` — built-in UV is locked. Re-invoke using the PIN path; a
  successful PIN validation via ClientPin unlocks built-in UV (only that or a
  factory reset will).
- ``pinAuthBlocked(source:)`` — clears on reinserting the authenticator.
- ``pinBlocked(source:)`` — requires a factory reset of the authenticator.
- ``forcePinChange(source:)`` — requires a PIN change before further PIN-using
  operations will succeed.

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
