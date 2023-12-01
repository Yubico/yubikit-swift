# ``YubiKit/Connection``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Topics

### Creating a Connection

- ``connection()``

### Managing the Connection

- ``close(error:)``
- ``connectionDidClose()``
- ``nfcConnection``

### Sending and receiving data to the YubiKey

- ``send(apdu:)``

### Errors

- ``ConnectionError``
- ``ResponseError``
- ``ResponseStatusCode``
