# ``YubiKit/CTAP2/GetAssertion``

Types for the CTAP2 authenticatorGetAssertion command (authentication).

## Overview

GetAssertion contains types for the authentication command. Use ``Parameters`` to specify the
relying party, allowed credentials, and extension inputs. The ``Response`` contains the
signed assertion proving possession of the credential.

```swift
let params = CTAP2.GetAssertion.Parameters(
    rpId: "example.com",
    clientDataHash: clientDataHash,
    allowList: [credentialDescriptor]
)
let response = try await session.getAssertion(parameters: params, token: pinToken).value
let signature = response.signature
```

## Topics

### Request

- ``Parameters``

### Response

- ``Response``
