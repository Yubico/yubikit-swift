# ``YubiKit/CTAP2/MakeCredential``

Types for the CTAP2 authenticatorMakeCredential command (credential registration).

## Overview

MakeCredential contains types for the credential registration command. Use ``Parameters`` to
specify the relying party, user account, supported algorithms, and extension inputs.
The ``Response`` contains the attestation object with the new credential's public key.

```swift
let params = CTAP2.MakeCredential.Parameters(
    clientDataHash: clientDataHash,
    rp: rpEntity,
    user: userEntity,
    pubKeyCredParams: [.es256, .rs256],
    rk: true  // discoverable credential
)
let response = try await session.makeCredential(parameters: params, token: pinToken).value
let credentialId = response.authenticatorData.attestedCredentialData?.credentialId
```

## Topics

### Request

- ``Parameters``

### Response

- ``Response``
