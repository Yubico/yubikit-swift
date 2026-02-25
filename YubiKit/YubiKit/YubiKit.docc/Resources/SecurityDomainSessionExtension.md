# ``YubiKit/SecurityDomainSession``

Session for managing SCP (Secure Channel Protocol) keys on the YubiKey.

## Overview

SecurityDomainSession provides access to the YubiKey's Security Domain application for
managing cryptographic keys used in secure channel establishment.

This is an advanced API for provisioning and managing SCP03/SCP11 keys.

```swift
let connection = try await USBSmartCardConnection()
let session = try await SecurityDomainSession.makeSession(connection: connection)

// Get information about stored keys
let keyInfo = try await session.getKeyInformation()
for (keyRef, components) in keyInfo {
    print("Key \(keyRef.kid)/\(keyRef.kvn): \(components)")
}

// Generate a new SCP11b key pair
let publicKey = try await session.generateECKey(
    for: SCPKeyRef(kid: .scp11b, kvn: 1),
    replacing: 0
)

// Factory reset (restores default keys)
try await session.reset()
```

> Important: Most applications don't need to use SecurityDomainSession directly.
> The SDK automatically handles secure channel establishment when you provide
> ``SCPKeyParams`` to session creation methods.

## Topics

### Creating a Session

- ``makeSession(connection:scpKeyParams:)``

### Key Information

- ``getKeyInformation()``
- ``getCardRecognitionData()``
- ``getCertificateBundle(for:)``
- ``getSupportedCAIdentifiers(kloc:klcc:)``

### Key Management

- ``generateECKey(for:replacing:)``
- ``putStaticKeys(_:for:replacing:)``
- ``putPublicKey(_:for:replacing:)``
- ``putPrivateKey(_:for:replacing:)``
- ``deleteKey(for:deleteLast:)``

### Certificate Management

- ``putCertificateBundle(_:for:)``
- ``putAllowlist(for:serials:)``
- ``putCAIssuer(for:ski:)``

### Data Operations

- ``getData(tag:data:)``
- ``putData(_:)``

### Reset

- ``reset()``

### Errors

- ``SCPError``
