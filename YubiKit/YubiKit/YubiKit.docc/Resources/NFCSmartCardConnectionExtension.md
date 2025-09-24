# ``YubiKit/NFCSmartCardConnection``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Creating a NFCSmartCardConnection

- ``connection()``
- ``connection(alertMessage:)``
- ``setAlertMessage(_:)``

### Managing the NFCSmartCardConnection

- ``close(error:)``
- ``close(message:)``
- ``waitUntilClosed()``
- ``nfcConnection``

### Sending data to the YubiKey

- ``SmartCardConnection/send(apdu:)``

### Errors

- ``NFCConnectionError``
