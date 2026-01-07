# PIVTool: Building PIV applications with YubiKey

This sample shows how to build applications that use YubiKeys for PIV (Personal Identity Verification) operations. The command-line tool demonstrates using ``PIVSession`` for cryptographic operations, certificate management, and access control.

@Metadata {
    @CallToAction(
        purpose: link,
        url: "https://github.com/Yubico/yubikit-swift/tree/main/Samples/yubikit-piv-tool")
    @PageKind(sampleCode)
    @PageColor(blue)
}

The PIV tool shows how to build applications that:
- Generate cryptographic keys directly on the YubiKey
- Manage certificates and perform digital signatures
- Handle PIN/PUK authentication and management keys
- Work with different key types (RSA, ECDSA, Ed25519, X25519)
- Query device capabilities and slot information

This sample demonstrates building secure applications where private keys never leave the YubiKey.

## Building PIV Applications

PIV applications provide strong security by keeping private keys in hardware while making them accessible for cryptographic operations. This sample demonstrates the key patterns:

- **Key lifecycle**: Generate keys on-device, get attestation, install certificates
- **Cryptographic operations**: Sign, decrypt, and key agreement operations
- **Access control**: Handle PIN, PUK, and management key authentication
- **Device management**: Query capabilities, manage slots, handle different YubiKey models
- **Error handling**: Graceful handling of authentication failures and device limitations

The typical PIV application workflow involves generating keys directly on the YubiKey, obtaining certificates from a Certificate Authority, then using those keys for authentication, document signing, or encrypted communications.

## Working with PIV Keys

### Key Generation

PIV applications typically generate keys directly on the YubiKey to ensure private keys never exist outside the secure element:

```swift
let publicKey = try await session.generateKey(
    in: .authentication,
    type: .rsa(.bits2048),
    pinPolicy: .always,
    touchPolicy: .never
)
```

The key generation returns the public key while keeping the private key secure on the YubiKey. You can generate different key types depending on your needs:

```swift
// RSA keys for traditional PKI compatibility
let rsaKey = try await session.generateKey(in: .authentication, type: .rsa(.bits2048))

// ECDSA keys for smaller signatures and better performance
let ecKey = try await session.generateKey(in: .signature, type: .ec(.secp256r1))

// Ed25519 for modern cryptographic applications
let ed25519Key = try await session.generateKey(in: .cardAuth, type: .ed25519)

// X25519 for key agreement/ECDH operations
let x25519Key = try await session.generateKey(in: .keyManagement, type: .x25519)
```

### PIN and Touch Policies

When generating keys, you control when authentication is required:

```swift
let key = try await session.generateKey(
    in: .signature,
    type: .ec(.secp256r1),
    pinPolicy: .once,      // PIN required once per session
    touchPolicy: .always   // Physical touch required for each operation
)
```

These policies provide different security levels depending on your application's requirements.

### Key Attestation

For compliance requirements, you can prove that keys were generated on the YubiKey:

```swift
let attestationCert = try await session.attestKey(in: .authentication)
// This certificate proves the key was generated in hardware, not imported
```

The attestation certificate is signed by Yubico's key and provides cryptographic proof that the key was generated on-device and hasn't been copied or imported.

## Certificate Management

PIV applications typically work with X.509 certificates paired with the private keys stored on the YubiKey.

### Storing Certificates

After generating a key or receiving a signed certificate, store it in the corresponding slot:

```swift
let certificateData = try Data(contentsOf: certificateURL)
let certificate = try Certificate(derEncoded: Array(certificateData))

try await session.putCertificate(
    certificate,
    in: .authentication,
    compressed: true  // Save space on the YubiKey
)
```

### Reading Certificates

Applications often need to read certificates for identity verification:

```swift
let certificate = try await session.getCertificate(in: .authentication)
// Use the certificate for identity verification, chain building, etc.
```

## Using PIV Keys for Cryptographic Operations

Once you have keys and certificates set up, you can use them for cryptographic operations. The private key never leaves the YubiKey - all operations happen on-device.

### Digital Signatures

Sign documents, challenges, or any data using the private key:

```swift
let documentHash = SHA256.hash(data: documentData)
let signature = try await session.sign(
    Data(documentHash),
    in: .signature,
    keyType: .ec(.secp256r1),
    using: .hash(.sha256)
)
```

This is commonly used for document signing, authentication challenges, or code signing applications.

### Decryption

For applications that encrypt data to the YubiKey's public key:

```swift
let decryptedData = try await session.decrypt(
    encryptedData,
    in: .keyManagement,
    using: .pkcs1v15
)
```

### Key Agreement

For secure communications, use ECDH to establish shared secrets:

```swift
let sharedSecret = try await session.deriveSharedSecret(
    in: .keyManagement,
    with: peerPublicKey
)
// Use the shared secret for symmetric encryption
```

## PIV Authentication and Access Control

PIV applications need to handle various authentication factors to protect access to private keys.

### PIN Authentication

Most PIV operations require PIN verification:

```swift
let pinResult = try await session.verifyPin("123456")
switch pinResult {
case .success:
    // PIN verified, can now use keys with PIN policies
case .fail(let attemptsRemaining):
    // Handle incorrect PIN, show remaining attempts
case .pinLocked:
    // PIN is locked, need to use PUK
}
```

### Management Key Authentication

Administrative operations require management key authentication:

```swift
let defaultManagementKey = Data(repeating: 0x01, count: 24) + Data(repeating: 0xff, count: 8)
try await session.authenticateWith(managementKey: defaultManagementKey)

// Now you can generate keys, install certificates, etc.
```

For production applications, change the default management key:

```swift
let newKey = try Data.random(length: 32)
try await session.setManagementKey(newKey, type: .aes256, requiresTouch: false)
```

### PIN Unlock (PUK) Operations

When PINs become locked, use the PUK to unlock:

```swift
try await session.unblockPinWithPuk("12345678", newPin: "123456")
```

## Querying PIV Information

### Checking What's in Each Slot

Before using a slot, check what's already there:

```swift
let metadata = try await session.getSlotMetadata(.authentication)
if metadata.generatedOnDevice {
    print("Key was generated on the YubiKey")
} else {
    print("Key was imported from outside")
}
```

### Feature Detection

Different YubiKey models support different features:

```swift
if await session.supports( .ed25519) {
    // Use modern Ed25519 keys
} else {
    // Fall back to RSA or ECDSA
}
```

This lets your application adapt to different YubiKey capabilities.

## Error Handling in PIV Applications

PIV operations can fail for various reasons - locked PINs, missing authentication, or unsupported operations. The PIV tool demonstrates comprehensive error handling with typed throws:

```swift
func verifyPinIfProvided(_ pin: String?) async {
    guard let pin = pin else { return }

    do {
        let result = try await verifyPin(pin)
        switch result {
        case .success:
            break
        case let .fail(retries):
            exitWithError("PIN verification failed - \(retries) tries left.")
        case .pinLocked:
            exitWithError("PIN is blocked.")
        }
    } catch {
        handlePIVError(error)
    }
}
```

The `handlePIVError` helper demonstrates matching on specific `PIVSessionError` cases:

```swift
func handlePIVError(_ error: PIVSessionError) {
    let message: String
    switch error {
    case let .failedResponse(responseStatus, _):
        let statusHex = String(format: "0x%04X", responseStatus.rawStatus)
        message = "YubiKey responded with status \(statusHex)"
    case let .invalidPin(retries, _):
        message = retries > 0 ? "PIN verification failed - \(retries) tries left." : "PIN is blocked."
    case .pinLocked:
        message = "PIN is blocked."
    case .authenticationFailed:
        message = "Authentication required."
    case .featureNotSupported:
        message = "Operation not supported by this YubiKey."
    // ... handle other cases
    }
    print("Error: \(message)")
}
```

With typed throws, the compiler ensures you handle all error cases specific to PIV operations.

