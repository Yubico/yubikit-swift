# ``YubiKit/Session``

Protocol for YubiKey application sessions.

## Overview

Session is the base protocol for application-specific sessions like ``OATHSession``,
``PIVSession``, and ``Management/Session``. Sessions provide typed APIs for interacting
with specific YubiKey applications.

Create sessions using the `makeSession(connection:)` factory method on the concrete session type.
Use ``supports(_:)`` to check for feature availability on the connected YubiKey.

## Topics

### Feature Support

- ``supports(_:)``

### Related Types

- ``SessionFeature``
