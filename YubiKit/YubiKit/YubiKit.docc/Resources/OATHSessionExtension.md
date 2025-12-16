# ``YubiKit/OATHSession``

## Topics

### Session Management

- ``reset()``
- ``supports(_:)``

### Credential Operations

- ``addCredential(template:)``
- ``renameCredential(_:newName:newIssuer:)``
- ``deleteCredential(_:)``
- ``listCredentials()``
- ``calculateCredentialCode(for:timestamp:)``
- ``calculateCredentialCodes(timestamp:)``
- ``calculateCredentialResponse(for:challenge:)``

### Access Protection

- ``setPassword(_:)``
- ``unlock(password:)``
- ``setAccessKey(_:)``
- ``unlock(accessKey:)``
- ``deleteAccessKey()``
- ``deriveAccessKey(from:)``

### Return Types

- ``Credential``
- ``Code``

### Errors

- ``OATHSessionError``
- ``CredentialTemplateError``

