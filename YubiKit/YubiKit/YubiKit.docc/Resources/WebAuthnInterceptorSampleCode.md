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

This sample bypasses the WebKit WebAuthn implementation and uses the YubiKit SDK instead, giving you full control over the authentication flow, PIN UI, and access to extensions like PRF.

## Architecture Overview

The sample consists of the following components:

- **Interceptor.js**: Injected into the WKWebView to intercept WebAuthn API calls
- **WebView.swift**: Sets up the WKWebView with the interceptor and message handlers
- **WebAuthnHandler.swift**: Manages YubiKey connection and PIN flow, delegates to client logic
- **WebAuthnClientLogic.swift**: Builds CTAP2 extension inputs and extracts results
- **WebAuthnTypes.swift**: Request/response types for JSON serialization between JS and Swift
- **PINEntryView.swift**: SwiftUI PIN entry UI and async handler
- **ContentView.swift**: Main UI with URL bar and navigation controls

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
        // Base64 encode to safely pass through the JS/Swift bridge
        window.webkit.messageHandlers.__webauthn_create__.postMessage(btoa(JSON.stringify(request)));
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
    // Decode the base64-encoded request from JavaScript
    guard let base64 = message.body as? String,
          let data = Data(base64Encoded: base64) else { return }

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
    results.prf = PRFOutput(prfResult)
}
```

During assertion (authentication), you get the actual derived secrets:

```swift
if let prf = state.prf, let secrets = try prf.getAssertion.output(from: response) {
    results.prf = PRFOutput(secrets)
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

## Binary Encoding

The WebAuthn API uses `ArrayBuffer` for binary fields, but WebKit's Swift-to-JavaScript bridge only supports JSON, which has no binary type. The sample uses base64url encoding for binary fields within the JSON structure. The entire message is then wrapped in standard base64 for transport.

### Requests (JS → Swift)

WebAuthn request options contain `ArrayBuffer` fields like `challenge` and `user.id`. The `encodeRequest` function recursively converts these to base64url strings before JSON serialization:

```javascript
function encodeRequest(obj) {
    if (obj instanceof ArrayBuffer) {
        return base64urlEncode(obj);
    }
    // recurse into objects/arrays...
}
```

### Responses (Swift → JS)

Swift wraps binary data as `{"__binary__": "<base64url>"}`. On the JavaScript side, a recursive function finds all `__binary__` markers and decodes them to `ArrayBuffer`:

```swift
struct BinaryValue: Codable {
    let __binary__: String
    init(_ data: Data) {
        self.__binary__ = data.base64urlEncodedString()
    }
}
```

This allows Swift to wrap any `Data` in `BinaryValue` without needing to know which specific fields the WebAuthn API expects as binary.

## Response Structure

The sample converts CTAP2 responses back to the expected WebAuthn structure:

```swift
struct CredentialResponse: Codable {
    let type: String
    let id: String?
    let rawId: BinaryValue?
    let response: AuthenticatorResponse
    let clientExtensionResults: ExtensionResults?
    let authenticatorAttachment: String?

    init(clientDataJSON: Data, makeCredentialResponse: CTAP2.MakeCredential.Response, extensionResults: ExtensionResults? = nil) {
        let credentialId = makeCredentialResponse.authenticatorData.attestedCredentialData?.credentialId
        self.type = "public-key"
        self.id = credentialId?.base64urlEncodedString()
        self.rawId = BinaryValue(credentialId)
        self.response = AuthenticatorResponse(clientDataJSON: clientDataJSON, makeCredentialResponse: makeCredentialResponse)
        self.clientExtensionResults = extensionResults
        self.authenticatorAttachment = "cross-platform"
    }
}
```

The response is then JSON-encoded and passed back to JavaScript via a callback:

```swift
let encodedResponse = Data(response.utf8).base64EncodedString()
_ = try? await webView?.evaluateJavaScript("__webauthn_callback__('\(encodedResponse)')")
```
