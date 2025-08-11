# ``YubiKit/SmartCardConnection``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Creating a SmartCardConnection

- ``connection()``

### Managing the SmartCardConnection

- ``close(error:)``
- ``connectionDidClose()``
- ``nfcConnection``

### Sending and receiving data to the YubiKey

- ``send(apdu:)``

### Errors

- ``ConnectionError``
- ``ResponseError``
- ``ResponseStatusCode``
