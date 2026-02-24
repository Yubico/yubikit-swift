# ``YubiKit/CTAP2/Error``

CTAP protocol-level errors returned by the authenticator.

## Overview

These error codes are defined in the CTAP specification and indicate specific failure
conditions during authenticator operations. They are wrapped in ``CTAP2/SessionError/ctapError(_:source:)``.

## Topics

### Common Errors

- ``pinInvalid``
- ``pinBlocked``
- ``pinNotSet``
- ``pinAuthInvalid``
- ``noCredentials``
- ``credentialExcluded``

### User Interaction Errors

- ``userActionTimeout``
- ``upRequired``
- ``keepaliveCancel``

### Authenticator State Errors

- ``uvBlocked``
- ``keyStoreFull``
- ``fpDatabaseFull``
- ``largeBlobStorageFull``

### Protocol Errors

- ``invalidCommand``
- ``invalidParameter``
- ``invalidLength``
- ``missingParameter``
- ``unsupportedAlgorithm``
- ``unsupportedExtension``
- ``unsupportedOption``
