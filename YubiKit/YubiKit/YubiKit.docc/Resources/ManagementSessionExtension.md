# ``YubiKit/ManagementSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the ManagementSession

- ``session(withConnection:)``
- ``end()``

### Running commands in the Management application

- ``getDeviceInfo()``
- ``updateDeviceConfig(_:reboot:lockCode:newLockCode:)``
- ``isApplicationSupported(_:overTransport:)``
- ``isApplicationEnabled(_:overTransport:)``
- ``setEnabled(_:application:overTransport:reboot:)``
- ``enableApplication(_:overTransport:reboot:)``
- ``disableApplication(_:overTransport:reboot:)``
- ``deviceReset()``

### Return types

- ``DeviceInfo``
- ``DeviceConfig``

### Enumerations

- ``Capability``
- ``DeviceTransport``
- ``FormFactor``
- ``ManagementFeature``

### Errors

- ``ManagementSessionError``
