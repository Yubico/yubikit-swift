# ``YubiKit/CTAP2/Session``

## Topics

### Authenticator Information

- ``getInfo()``
- ``selection()``
- ``reset()``

### Credential Operations

- ``makeCredential(parameters:token:)``
- ``getAssertion(parameters:token:)``
- ``getAssertions(parameters:token:)``
- ``getNextAssertion()``

### PIN/UV Authentication

- ``getPinUVToken(using:permissions:rpId:protocol:)``
- ``setPin(_:protocol:)``
- ``changePin(from:to:protocol:)``
- ``getPinRetries(protocol:)``
- ``getUVRetries(protocol:)``

### Feature Accessors

- ``config(token:)``
- ``credentialManagement(token:)``
- ``bioEnrollment(token:)``

### Large Blobs

- ``supportsLargeBlobs()``
- ``getBlob(key:)``
- ``putBlob(key:data:token:)``
- ``deleteBlob(key:token:)``

### Related Types

- ``CTAP2/Token``
- ``CTAP2/Config``
- ``CTAP2/CredentialManagement``
- ``CTAP2/BioEnrollment``
- ``CTAP2/GetInfo``
- ``CTAP2/MakeCredential``
- ``CTAP2/GetAssertion``
- ``CTAP2/StatusStream``

### Extensions

- ``CTAP2/Extension``

### Errors

- ``CTAP2/SessionError``
