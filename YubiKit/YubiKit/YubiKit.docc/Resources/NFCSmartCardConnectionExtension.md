# ``YubiKit/NFCSmartCardConnection``

## Topics

### Creating a Connection

- ``makeConnection()``
- ``makeConnection(alertMessage:)``
- ``setAlertMessage(_:)``

### Connection Lifecycle

- ``close(error:)``
- ``close(message:)``
- ``waitUntilClosed()``

### Sending Data

- ``send(data:)``

### Errors

- ``SmartCardConnectionError``
