# ``YubiKit/ManagementSession``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Managing the ManagementSession

- ``session(withConnection:)``
- ``end()``
- ``sessionDidEnd()``

### Running commands in the Management application

- ``getDeviceInfo()``
- ``isApplicationSupported(_:overTransport:)``
- ``isApplicationEnabled(_:overTransport:)``
- ``setEnabled(_:application:overTransport:reboot:)``
- ``enableApplication(_:overTransport:reboot:)``
- ``disableApplication(_:overTransport:reboot:)``

### Return types

- ``DeviceInfo``
- ``DeviceConfig``

### Errors

- ``ManagementSessionError``
