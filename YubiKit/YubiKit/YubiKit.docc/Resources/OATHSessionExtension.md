# ``YubiKit/OATHSession``

Session for OATH (TOTP/HOTP) operations on the YubiKey.

## Overview

OATHSession manages TOTP and HOTP credentials stored on the YubiKey. Use it to add, list,
calculate, and delete authentication credentials.

```swift
let connection = try await NFCSmartCardConnection()
let session = try await OATHSession.makeSession(connection: connection)

// Calculate all codes at once
let codes = try await session.calculateCredentialCodes()
for (credential, code) in codes {
    print("\(credential.label): \(code?.code ?? "touch required")")
}

// Add a new credential
let template = CredentialTemplate(...)
try await session.addCredential(template: template)
```

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

