# ``YubiKit/OATHSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the OATHSession

- ``session(connection:scpKeyParams:)``
- ``end()``
- ``reset()``

### Running commands in the OATH application

- ``addCredential(template:)``
- ``renameCredential(_:newName:newIssuer:)``
- ``deleteCredential(_:)``
- ``listCredentials()``
- ``calculateCode(credential:timestamp:)``
- ``calculateCodes(timestamp:)``
- ``calculateResponse(credentialId:challenge:)``
- ``deriveAccessKey(from:)``
- ``setAccessKey(_:)``
- ``setPassword(_:)``
- ``unlockWithAccessKey(_:)``
- ``unlockWithPassword(_:)``

### Return types

- ``Credential``
- ``Code``

### Errors

- ``OATHSessionError``
- ``CredentialTemplateError``
- ``DeriveAccessKeyError``

