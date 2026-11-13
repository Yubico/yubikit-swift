# ``YubiKit/CTAP2/StatusStream``

Async sequence for consuming CTAP2 operation status updates.

## Overview

Long-running CTAP2 operations return a `StatusStream` that yields status updates
during execution. For simple cases, use the ``value`` property to await the final result.
For UI integration, iterate the stream to react to status changes.

Cancelling the task that consumes the stream ends its wait. The SDK cancels touch
waits through the transport protocol and finishes any exchange already in progress.
Cancellation does not undo a command that the authenticator has already received.

Further commands on the same CTAP2 session wait until the previous exchange finishes.
A command cancelled while queued returns without sending a request to the authenticator.

## Topics

### Getting the Result

- ``value``

### Status Values

- ``CTAP2/Status``
