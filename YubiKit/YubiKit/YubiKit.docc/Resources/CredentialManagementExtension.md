# ``YubiKit/CTAP2/CredentialManagement``

Operations for managing discoverable (resident) credentials stored on the authenticator.

## Overview

CredentialManagement allows listing, inspecting, and deleting discoverable credentials.
It requires a PIN/UV auth token with the ``CTAP2/ClientPin/Permission/credentialManagement`` permission.

```swift
let token = try await session.getPinUVToken(
    using: .pin("123456"),
    permissions: [.credentialManagement]
)
let credMgmt = try await session.credentialManagement(token: token)

// Get storage metadata
let metadata = try await credMgmt.getMetadata()
print("Stored: \(metadata.existingCredentialsCount)")
print("Remaining: \(metadata.maxRemainingCredentialsCount)")

// List credentials by relying party
for try await rp in credMgmt.rps {
    print("RP: \(rp.rp.id)")
    for try await cred in credMgmt.credentials(for: rp.rpIdHash) {
        print("  - \(cred.user.name ?? "unknown")")
    }
}

// Delete a credential
try await credMgmt.deleteCredential(credentialDescriptor)
```

## Topics

### Feature Detection

- ``isSupported(by:)``
- ``isUpdateSupported(by:)``
- ``isReadOnlySupported(by:)``

### Metadata

- ``getMetadata()``

### Listing Credentials

- ``rps``
- ``credentials(for:)``

### Managing Credentials

- ``deleteCredential(_:)``
- ``updateUserInformation(credentialId:user:)``

### Related Types

- ``Metadata``
- ``RPData``
- ``CredentialData``
- ``RPSequence``
- ``CredentialSequence``
