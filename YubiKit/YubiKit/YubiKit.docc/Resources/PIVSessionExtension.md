# ``YubiKit/PIVSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the PIVSession

- ``session(withConnection:)``
- ``end()``
- ``reset()``

### Running commands in the PIV application

- ``supports(_:)``
- ``signWithKeyInSlot(_:keyType:algorithm:message:)``
- ``decryptWithKeyInSlot(slot:algorithm:encrypted:)``
- ``calculateSecretKeyInSlot(slot:peerPublicKey:)``
- ``attestKeyInSlot(slot:)``
- ``generateKeyInSlot(slot:type:pinPolicy:touchPolicy:)``
- ``putKey(key:inSlot:pinPolicy:touchPolicy:)``
- ``putCertificate(certificate:inSlot:compress:)``
- ``getCertificateInSlot(_:)``
- ``deleteCertificateInSlot(slot:)``
- ``setManagementKey(_:type:requiresTouch:)``
- ``authenticateWith(managementKey:keyType:)``
- ``getSlotMetadata(_:)``
- ``getManagementKeyMetadata()``
- ``reset()``
- ``getSerialNumber()``
- ``verifyPin(_:)``
- ``setPin(_:oldPin:)``
- ``setPuk(_:oldPuk:)``
- ``unblockPinWithPuk(_:newPin:)``
- ``getPinMetadata()``
- ``getPukMetadata()``
- ``getPinAttempts()``
- ``set(pinAttempts:pukAttempts:)``
- ``blockPin(counter:)``
- ``blockPuk(counter:)``



### Return types

- ``PIVTouchPolicy``
- ``PIVPinPolicy``
- ``PIVSlot``
- ``PIVKeyType``
- ``PIVVerifyPinResult``
- ``PIVManagementKeyMetadata``
- ``PIVSlotMetadata``
- ``PIVPinPukMetadata``
- ``PIVManagementKeyType``

### Errors

- ``PIVSessionError``

