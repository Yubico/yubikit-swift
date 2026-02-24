# ``YubiKit/PIVSession``

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

