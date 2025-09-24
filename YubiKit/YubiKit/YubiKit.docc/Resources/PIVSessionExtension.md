# ``YubiKit/PIVSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the PIVSession

- ``session(connection:scpKeyParams:)``
- ``end()``
- ``reset()``

### Running commands in the PIV application

- ``hasSupport(for:)``
- ``signWithKeyInSlot(_:keyType:algorithm:message:)``
- ``decrypt(in:algorithm:encrypted:)``
- ``deriveSharedSecret(in:with:)``
- ``attestKey(in:)``
- ``generateKey(in:type:pinPolicy:touchPolicy:)``
- ``put(privateKey:in:pinPolicy:touchPolicy:)``
- ``put(certificate:in:compress:)``
- ``getCertificate(in:)``
- ``deleteCertificateInSlot(slot:)``
- ``setManagementKey(_:type:requiresTouch:)``
- ``authenticateWith(managementKey:)``
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
- ``set(pinAttempts:pukAttempts:)``
- ``blockPin(counter:)``
- ``blockPuk(counter:)``
- ``getBioMetadata()``
- ``verifyUV(requestTemporaryPin:checkOnly:)``
- ``verify(temporaryPin:)``

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
- ``PIVBioMetadata``

### PIV Session features

- ``PIVSessionFeature``

### Errors

- ``PIVSessionError``
- ``PIVPaddingError``

