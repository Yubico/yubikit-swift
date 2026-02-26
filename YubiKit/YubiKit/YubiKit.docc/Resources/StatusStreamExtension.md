# ``YubiKit/CTAP2/StatusStream``

Async sequence for consuming CTAP2 operation status updates.

## Overview

Long-running CTAP2 operations return a `StatusStream` that yields status updates
during execution. For simple cases, use the ``value`` property to await the final result.
For UI integration, iterate the stream to react to status changes.

## Topics

### Getting the Result

- ``value``

### Status Values

- ``CTAP2/Status``
