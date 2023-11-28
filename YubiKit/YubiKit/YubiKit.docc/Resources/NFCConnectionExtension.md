# ``YubiKit/NFCConnection``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Creating a NFCConnection

- ``connection()``
- ``connection(alertMessage:)``
- ``setAlertMessage(_:)``

### Managing the NFCConnection

- ``close(error:)``
- ``close(message:)``
- ``connectionDidClose()``

### Sending data to the YubiKey

- ``Connection/send(apdu:)``
