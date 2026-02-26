# ``YubiKit/CTAP2/HIDError``

CTAPHID transport-layer errors returned by the authenticator.

## Overview

These errors indicate problems at the HID transport level, as opposed to CTAP2 protocol-level errors.
They are wrapped in ``CTAP2/SessionError/hidError(_:source:)``.

## Topics

### Transport Errors

- ``invalidCmd``
- ``invalidPar``
- ``invalidLen``
- ``invalidSeq``
- ``msgTimeout``
- ``channelBusy``
- ``lockRequired``
- ``invalidChannel``
- ``other``
