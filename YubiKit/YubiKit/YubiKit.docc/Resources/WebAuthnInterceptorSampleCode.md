# WebAuthnInterceptorSample: FIDO2/WebAuthn client for WKWebView

This sample shows how to build a FIDO2/WebAuthn client that intercepts `navigator.credentials.{create,get}` calls inside a `WKWebView` and routes them to a YubiKey. It uses the high-level ``WebAuthn/Client`` API and delegates the entire ceremony — transport, PIN/UV prompts, errors, cancellation — to a small `FidoUI` companion module.

@Metadata {
    @CallToAction(
        purpose: link,
        url: "https://github.com/Yubico/yubikit-swift/tree/main/Samples/WebAuthnInterceptorSample")
    @PageKind(sampleCode)
    @PageColor(yellow)
}

The interceptor demonstrates how to:
- Intercept `navigator.credentials.create()` and `navigator.credentials.get()` in a `WKWebView`.
- Round-trip WebAuthn Level 3 JSON directly into the SDK's ``WebAuthn/Registration/Options`` / ``WebAuthn/Authentication/Options`` types.
- Drive the SDK's high-level ``WebAuthn/Client`` ceremony without hand-rolling CTAP2 plumbing, PIN retry, or extension wiring.
- Use the bundled `FidoUI` module for transport selection (USB-C / Lightning / NFC on iOS, HID on macOS) and for the PIN, UV, error, and success panels.

By bypassing WebKit's built-in WebAuthn implementation you get full control over which authenticator handles the request, the look and feel of the prompts, and access to extensions that the platform doesn't otherwise surface.

## Architecture Overview

The sample itself is intentionally thin:

- **Interceptor.js** — injected into the `WKWebView` to monkey-patch `navigator.credentials.{create,get}` and shuttle requests/responses through `WKScriptMessageHandler`.
- **WebView.swift** — `UIViewRepresentable` / `NSViewRepresentable` wrapper that installs the script, registers message handlers, and coordinates ceremony lifecycle (cancel on dismiss, cancel-and-replace on a new request).
- **WebAuthnHandler.swift** — decodes the JSON envelope, builds a ``WebAuthn/Origin``, and calls `FidoUI.makeCredential` / `FidoUI.getAssertion`.
- **ContentView.swift** — minimal SwiftUI shell with a URL bar and back button.
- **FidoUI** (separate Swift package under `Samples/WebAuthnInterceptorSample/FidoUI`) — the reusable UI + transport layer described below.

The end-to-end flow:
1. Page JS calls `navigator.credentials.create()` / `.get()`; the interceptor serializes the options as WebAuthn Level 3 JSON and posts it to Swift.
2. `WebAuthnHandler` decodes the JSON straight into the SDK's strongly-typed `Options` and hands them to `FidoUI`.
3. `FidoUI` opens a transport, runs the ceremony via ``WebAuthn/Client``, and shows PIN / UV / error / success panels as needed.
4. The resulting ``WebAuthn/Registration/Response`` or ``WebAuthn/Authentication/Response`` is serialized via its built-in `toJSON()` and posted back to JS.

## Intercepting WebAuthn Calls

### JavaScript Injection

`Interceptor.js` replaces `navigator.credentials.create` and `navigator.credentials.get` with versions that forward to Swift. Binary fields (`challenge`, `user.id`, `rawId`, …) are serialized to **base64url** strings via `JSON.stringify` with a replacer — this matches the WebAuthn Level 3 JSON format the SDK consumes natively, so no custom binary-wrapping protocol is needed.

```javascript
function interceptWebAuthn(type, options, originalFn) {
    if (!shouldIntercept(options)) return originalFn(options);

    return new Promise((resolve, reject) => {
        pendingResolve = resolve;
        pendingReject = reject;

        const publicKey = serializePublicKeyOptionsToJSON(options.publicKey);
        if (type === 'create' && publicKey.rp && !publicKey.rp.id) {
            publicKey.rp.id = window.location.hostname;
        }

        const request = { type, origin: window.location.origin, request: publicKey };
        window.webkit.messageHandlers[`__webauthn_${type}__`]
            .postMessage(btoa(JSON.stringify(request)));
    });
}
```

The script is injected at document start so it runs before any page code:

```swift
let script = WKUserScript(
    source: interceptorScript,
    injectionTime: .atDocumentStart,
    forMainFrameOnly: true
)
config.userContentController.addUserScript(script)
```

`shouldIntercept` returns `true` for any `publicKey`-bearing request, but is the natural seam for narrower policies (e.g. only intercept when `publicKey.hints` includes `"security-key"`).

### Receiving Messages in Swift

The `Coordinator` is both `WKNavigationDelegate` and `WKScriptMessageHandler`. Each incoming message starts a fresh ceremony, cancelling any in-flight one first:

```swift
func userContentController(
    _ userContentController: WKUserContentController,
    didReceive message: WKScriptMessage
) {
    guard let base64 = message.body as? String,
          let data = Data(base64Encoded: base64) else { return }

    ceremonyGeneration += 1
    let generation = ceremonyGeneration
    activeTask?.cancel()
    activeTask = Task {
        await handler.cancelActiveCeremony()
        await handleWebAuthnMessage(name: message.name, data: data, generation: generation)
    }
}
```

`shutdown()` is called from `dismantle{UI,NS}View` so navigating away mid-ceremony unwinds the open NFC/HID handle.

## Driving the Ceremony

`WebAuthnHandler` is intentionally tiny — it decodes the envelope, builds a typed `Origin`, and delegates to `FidoUI`. There is no manual CTAP2 code, no PIN loop, and no extension plumbing in the sample itself.

```swift
struct WebAuthnRequest<Options: Decodable>: Decodable {
    let origin: String
    let publicKey: Options
    enum CodingKeys: String, CodingKey { case origin; case publicKey = "request" }
}

func handleCreate(_ data: Data) async throws -> String {
    let request = try JSONDecoder().decode(
        WebAuthnRequest<WebAuthn.Registration.Options>.self,
        from: data
    )
    let origin = try WebAuthn.Origin(request.origin)
    let response = try await fidoUI.makeCredential(
        request.publicKey,
        origin: origin,
        serviceName: origin.host
    )
    return String(decoding: try response.toJSON(), as: UTF8.self)
}
```

`handleGet` is the symmetric counterpart that decodes ``WebAuthn/Authentication/Options`` and calls `fidoUI.getAssertion`. The response JSON produced by `toJSON()` is already in WebAuthn Level 3 format with base64url-encoded binary fields, so the JS side just decodes those back to `ArrayBuffer` when it materializes the credential.

## Returning the Response to JavaScript

The Swift-side response is JSON-encoded, base64-wrapped for the bridge, and handed back via a callback installed by the interceptor:

```swift
let encodedResponse = Data(response.utf8).base64EncodedString()
_ = try? await webView?.evaluateJavaScript(
    "__webauthn_callback__('\(encodedResponse)')"
)
```

JavaScript decodes the JSON and rebuilds a `PublicKeyCredential`-shaped object — converting the base64url binary fields back to `ArrayBuffer`s and wiring up `getClientExtensionResults`, `getAuthenticatorData`, `getPublicKey`, `toJSON`, and the rest. Errors travel through a parallel `__webauthn_error__` channel and surface to the page as a `DOMException` with name `NotAllowedError`.

## The FidoUI Module

`FidoUI` is a `@MainActor` Swift package shipped alongside the sample, and it does most of the work. Intercepting `navigator.credentials.*` means giving up the platform's built-in WebAuthn sheets (tap prompt, PIN entry, errors, success) — `FidoUI` replaces them end-to-end with a complete ceremony UI: connect / touch, PIN entry with retry counters, PIN change, first-time PIN setup, forced PIN-change recovery, fingerprint enrollment, credential picker, and error / success results. The host app stays a thin shell.

Beyond the panels, it owns the moving parts that you'd otherwise re-implement per app:

- **Transport selection.** On iOS it tries wired (USB-C / Lightning) first and falls back to NFC; on macOS it uses HID FIDO. Connections are polled and reused across a ceremony.
- **Ceremony serialization.** Concurrent calls on the same `FidoUI` instance are queued so they don't fight over the alert window, transport, or shared panel state.
- **Cancellation.** A single `cancel()` call (used by the WebView coordinator on dismiss / new message) tears down the active transport and dismisses any visible panel.

The host code only needs to construct one `FidoUI` instance and call `makeCredential` / `getAssertion` per request — everything else (PIN prompts, UV policy, transport lifecycle, error UI) is handled internally. See `Samples/WebAuthnInterceptorSample/FidoUI/` for the full source.

## Platform Notes

- **iOS.** The wired path goes through CryptoTokenKit (`WiredSmartCardConnection` — USB-C or Lightning), and the NFC path through `NFCSmartCardConnection`. The sample's `Info.plist` declares `NFCReaderUsageDescription` and lists the FIDO applet AID (`A0000006472F0001`) under `com.apple.developer.nfc.readersession.iso7816.select-identifiers`; the entitlements turn on `com.apple.developer.nfc.readersession.formats` (`TAG`) and `com.apple.security.smartcard`.
- **macOS.** `FidoUI` uses ``HIDFIDOConnection`` directly. The HID path itself doesn't need the smart-card entitlement, but the sample enables `com.apple.security.smartcard` and `com.apple.security.device.usb` so the same target builds cleanly for both platforms.

## Where to Customize

- **Which requests get intercepted.** Edit `shouldIntercept` in `Interceptor.js` to scope by hint, RP ID, or any other heuristic.
- **Origin verification.** `WebAuthnHandler` builds a ``WebAuthn/Origin`` from `window.location.origin`. Replace the `isPublicSuffix` closure passed to `FidoUI` with a real public-suffix-list check before shipping.
- **UI.** Swap or restyle the panels in `FidoUI/Sources/FidoUI/Views/` — the rest of the module is UI-agnostic.
