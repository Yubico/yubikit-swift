# ``YubiKit/PIVSession``

Session for PIV (Personal Identity Verification) smart card operations.

## Overview

PIVSession provides access to the PIV application on the YubiKey for certificate-based
authentication, digital signatures, and key management. Private keys are generated and
stored securely on the YubiKey and never leave the device.

```swift
let connection = try await USBSmartCardConnection()
let session = try await PIVSession.makeSession(connection: connection)

// Authenticate with management key for administrative operations
try await session.authenticate(with: managementKey)

// Generate a key pair (private key stays on YubiKey)
let publicKey = try await session.generateKey(
    in: .authentication,
    type: .ec(.secp256r1),
    pinPolicy: .once,
    touchPolicy: .never
)

// Sign data with the private key
try await session.verifyPin("123456")
let signature = try await session.sign(data, in: .authentication, keyType: .ec(.secp256r1), using: .sha256)
```

## Topics

### Session Management

- ``reset()``
- ``supports(_:)``

### Cryptographic Operations

- ``sign(_:in:keyType:using:)-204it``
- ``sign(_:in:keyType:using:)-7bmau``
- ``sign(_:in:keyType:)``
- ``decrypt(_:in:using:)``
- ``deriveSharedSecret(in:with:)-72vkx``
- ``deriveSharedSecret(in:with:)-3o9ip``

### Key Management

- ``generateKey(in:type:pinPolicy:touchPolicy:)``
- ``attestKey(in:)``
- ``moveKey(from:to:)``
- ``deleteKey(in:)``
- ``getMetadata(in:)``

### Certificate Operations

- ``putCertificate(_:in:compressed:)``
- ``getCertificate(in:)``
- ``deleteCertificate(in:)``

### Authentication

- ``authenticate(with:)``
- ``setManagementKey(_:type:requiresTouch:)``
- ``getManagementKeyMetadata()``
- ``verifyPin(_:)``
- ``changePin(from:to:)``
- ``changePuk(from:to:)``
- ``unblockPin(with:newPin:)``
- ``setRetries(pin:puk:)``
- ``blockPin()``
- ``blockPuk()``
- ``getPinMetadata()``
- ``getPukMetadata()``

### Biometric Operations

- ``getBioMetadata()``
- ``verifyUV(requestTemporaryPin:checkOnly:)``
- ``verify(temporaryPin:)``

### Device Information

- ``getSerialNumber()``

### Features

- ``PIVSessionFeature``

### Errors

- ``PIVSessionError``

