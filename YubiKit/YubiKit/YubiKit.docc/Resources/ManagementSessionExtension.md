# ``YubiKit/ManagementSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the ManagementSession

- ``session(connection:scpKeyParams:)``
- ``end()``

### Running commands in the Management application

- ``deviceInfo()``
- ``updateDeviceConfig(_:reboot:lockCode:newLockCode:)``
- ``isApplicationSupported(_:over:)``
- ``isApplicationEnabled(_:over:)``
- ``enable(_:over:reboot:)``
- ``disable(_:over:reboot:)``
- ``deviceReset()``

### Return types

- ``Device/Info``
- ``Device/Config``

### Enumerations

- ``Capability``
- ``Device.Transport``
- ``FormFactor``
- ``ManagementFeature``

### Errors

- ``ManagementSessionError``
