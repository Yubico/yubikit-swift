# WebAuthnInterceptorSample: FIDO2/WebAuthn client for WKWebView

This sample shows how to build a FIDO2 client that intercepts WebAuthn API calls in a WKWebView and routes them to a YubiKey via NFC (iOS) or USB HID (macOS). The app demonstrates using ``CTAP2/Session`` for FIDO2 operations and handling the PRF extension for deriving secrets.

@Metadata {
    @CallToAction(
        purpose: link,
        url: "https://github.com/Yubico/yubikit-swift/tree/main/Samples/WebAuthnInterceptorSample")
    @PageKind(sampleCode)
    @PageColor(yellow)
}

The WebAuthn interceptor shows how to build applications that:
- Intercept `navigator.credentials.create()` and `navigator.credentials.get()` in a WKWebView
- Convert between WebAuthn API types and CTAP2 protocol structures
- Handle PIN entry with retry logic
- Support the PRF extension (hmac-secret) for deriving cryptographic secrets
- Connect via NFC on iOS or USB HID on macOS

This sample enables using hardware security keys on websites that don't natively support them, by acting as a WebAuthn client that bridges the browser API to the YubiKey.

## Architecture Overview

The sample consists of three main components:

- **Interceptor.js**: Injected into the WKWebView to intercept WebAuthn API calls
- **Bridge.swift**: Converts WebAuthn requests to CTAP2 commands and handles YubiKey communication
- **WebView.swift**: Sets up the WKWebView with the interceptor and message handlers

The flow works as follows:
1. JavaScript intercepts `navigator.credentials.create()` or `navigator.credentials.get()`
2. The request is serialized and sent to Swift via `WKScriptMessageHandler`
3. Swift converts the request to CTAP2 format and communicates with the YubiKey
4. The response is converted back to WebAuthn format and returned to JavaScript

## Intercepting WebAuthn Calls

### JavaScript Injection

The interceptor replaces the browser's WebAuthn API with custom implementations:

```javascript
const originalCreate = navigator.credentials.create.bind(navigator.credentials);
const originalGet = navigator.credentials.get.bind(navigator.credentials);

navigator.credentials.create = function(options) {
    console.log('[WebAuthn] Intercepting create');
    return new Promise((resolve, reject) => {
        pendingResolve = resolve;
        pendingReject = reject;

        const request = {
            type: 'create',
            origin: window.location.origin,
            request: encodeRequest(options.publicKey)
        };
        window.webkit.messageHandlers.__webauthn_create__.postMessage(JSON.stringify(request));
    });
};
```

The script is injected at document start to ensure it runs before any website code:

```swift
let script = WKUserScript(
    source: interceptorScript,
    injectionTime: .atDocumentStart,
    forMainFrameOnly: true
)
config.userContentController.addUserScript(script)
```

### Receiving Messages in Swift

The `Coordinator` class implements `WKScriptMessageHandler` to receive the intercepted requests:

```swift
func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
    guard let body = message.body as? String,
          let data = body.data(using: .utf8) else { return }

    Task {
        await handleWebAuthnMessage(name: message.name, data: data)
    }
}
```

## CTAP2 Communication

### Creating Credentials

The `handleCreate` method converts WebAuthn `PublicKeyCredentialCreationOptions` to CTAP2 `MakeCredential` parameters:

```swift
func handleCreate(_ data: Data) async throws -> String {
    let wrapper = try JSONDecoder().decode(CreateRequestWrapper.self, from: data)
    let request = wrapper.request

    let session = try await makeSession()

    let rpEntity = WebAuthn.PublicKeyCredential.RPEntity(
        id: request.rp.id,
        name: request.rp.name
    )
    let userEntity = WebAuthn.PublicKeyCredential.UserEntity(
        id: Data(base64urlDecoding: request.user.id) ?? Data(),
        name: request.user.name,
        displayName: request.user.displayName
    )

    let params = CTAP2.MakeCredential.Parameters(
        clientDataHash: clientDataHash,
        rp: rpEntity,
        user: userEntity,
        pubKeyCredParams: pubKeyParams,
        excludeList: excludeList,
        extensions: extState.inputs,
        options: options
    )

    let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value
    // Convert response back to WebAuthn format...
}
```

### Getting Assertions

Similarly, `handleGet` converts `PublicKeyCredentialRequestOptions` to CTAP2 `GetAssertion`:

```swift
func handleGet(_ data: Data) async throws -> String {
    let wrapper = try JSONDecoder().decode(GetRequestWrapper.self, from: data)
    let request = wrapper.request

    let session = try await makeSession()

    let params = CTAP2.GetAssertion.Parameters(
        rpId: request.rpId,
        clientDataHash: clientDataHash,
        allowList: allowList,
        extensions: extState.inputs,
        options: options
    )

    let response = try await session.getAssertion(parameters: params, pinToken: pinToken).value
    // Convert response back to WebAuthn format...
}
```

## PIN Handling

The sample implements a PIN retry loop that prompts the user when verification fails. If the YubiKey has a PIN configured, it requests a PIN token using `session.getPinUVToken()` before performing CTAP2 operations. Invalid PIN attempts are caught and the user is prompted to retry.

## PRF Extension (hmac-secret)

The PRF extension allows deriving cryptographic secrets from credentials. This is useful for encryption keys that are bound to both the credential and user-provided salts.

### Requesting PRF During Credential Creation

```swift
if let prfEval = request.extensions?.prf?.eval,
   let firstData = Data(base64urlDecoding: prfEval.first) {
    let prf = try await WebAuthn.Extension.PRF(session: session)
    let secondData = prfEval.second.flatMap { Data(base64urlDecoding: $0) }
    state.inputs.append(try prf.makeCredential.input(first: firstData, second: secondData))
    state.prf = prf
} else if request.extensions?.prf != nil {
    // Just enable PRF without evaluating
    let prf = try await WebAuthn.Extension.PRF(session: session)
    state.inputs.append(prf.makeCredential.input())
    state.prf = prf
}
```

### Extracting PRF Results

During credential creation, you typically get confirmation that PRF is enabled:

```swift
if let prf = state.prf, let prfResult = try prf.makeCredential.output(from: response) {
    switch prfResult {
    case .enabled:
        results.prf = PRFOutput(enabled: true)
    case .secrets(let secrets):
        results.prf = PRFOutput(
            first: secrets.first.base64urlEncodedString(),
            second: secrets.second?.base64urlEncodedString()
        )
    }
}
```

During assertion (authentication), you get the actual derived secrets:

```swift
if let prf = state.prf, let secrets = try prf.getAssertion.output(from: response) {
    results.prf = PRFOutput(
        first: secrets.first.base64urlEncodedString(),
        second: secrets.second?.base64urlEncodedString()
    )
}
```

The secrets are 32-byte HMAC-SHA256 outputs derived from the credential's secret key and the provided salt values. These are deterministic - the same salts always produce the same outputs for a given credential.

## Platform-Specific Connections

The sample handles iOS and macOS differently:

```swift
private func makeSession() async throws -> CTAP2.Session {
    #if os(iOS)
    let conn = try await NFCSmartCardConnection(alertMessage: "Tap your YubiKey")
    #else
    let conn = try await HIDFIDOConnection()
    #endif

    connection = conn
    let session = try await CTAP2.Session.makeSession(connection: conn)
    return session
}
```

On iOS, NFC provides a system dialog prompting the user to tap their YubiKey. On macOS, USB HID waits for a FIDO-capable device to be connected.

## Response Encoding

The WebAuthn API expects specific response formats. The sample converts CTAP2 responses back to the expected structure:

```swift
struct CredentialResponse: Codable {
    let type: String
    let id: String?
    let rawId: String?
    let response: AuthenticatorResponse
    let clientExtensionResults: ExtensionResults?
    let authenticatorAttachment: String?

    init(clientDataJSON: Data, makeCredentialResponse: CTAP2.MakeCredential.Response, extensionResults: ExtensionResults? = nil) {
        let credentialId = makeCredentialResponse.authenticatorData.attestedCredentialData?.credentialId.base64urlEncodedString()
        self.type = "public-key"
        self.id = credentialId
        self.rawId = credentialId
        self.response = AuthenticatorResponse(clientDataJSON: clientDataJSON, makeCredentialResponse: makeCredentialResponse)
        self.clientExtensionResults = extensionResults
        self.authenticatorAttachment = "cross-platform"
    }
}
```

The response is then JSON-encoded and passed back to JavaScript via a callback:

```swift
let js = "__webauthn_callback__('\(response.escapedForJavaScript())')"
try? await webView?.evaluateJavaScript(js)
```

