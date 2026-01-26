/// WKWebView wrapper that injects the WebAuthn interceptor script and handles
/// message passing between JavaScript and Swift.

import SwiftUI
import WebKit

// MARK: - Constants

private enum MessageHandler {
    static let create = "__webauthn_create__"
    static let get = "__webauthn_get__"
    static let all = [create, get]
}

// MARK: - Navigator

@MainActor
class WebViewNavigator: ObservableObject {
    @Published var canGoBack = false

    weak var webView: WKWebView? {
        didSet {
            observation = webView?.observe(\.canGoBack, options: [.initial, .new]) { [weak self] webView, _ in
                Task { @MainActor in self?.canGoBack = webView.canGoBack }
            }
        }
    }

    private var observation: NSKeyValueObservation?

    func goBack() {
        webView?.goBack()
    }
}

// MARK: - WebView (Platform-Specific)

#if os(iOS)
struct WebView: UIViewRepresentable {
    let url: URL
    let pinHandler: PINRequestHandler
    let navigator: WebViewNavigator

    func makeUIView(context: Context) -> WKWebView {
        let webView = createWebView(context: context)
        navigator.webView = webView
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        updateWebView(webView)
    }

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        cleanupWebView(webView)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(pinHandler: pinHandler)
    }
}
#else
struct WebView: NSViewRepresentable {
    let url: URL
    let pinHandler: PINRequestHandler
    let navigator: WebViewNavigator

    func makeNSView(context: Context) -> WKWebView {
        let webView = createWebView(context: context)
        navigator.webView = webView
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        updateWebView(webView)
    }

    static func dismantleNSView(_ webView: WKWebView, coordinator: Coordinator) {
        cleanupWebView(webView)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(pinHandler: pinHandler)
    }
}
#endif

// MARK: - WebView Configuration

extension WebView {
    static func cleanupWebView(_ webView: WKWebView) {
        let controller = webView.configuration.userContentController
        for name in MessageHandler.all {
            controller.removeScriptMessageHandler(forName: name)
        }
    }

    func createWebView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let coordinator = context.coordinator

        if let interceptorScript = loadInterceptorScript() {
            let script = WKUserScript(
                source: interceptorScript,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
            config.userContentController.addUserScript(script)
        }

        for name in MessageHandler.all {
            config.userContentController.add(coordinator, name: name)
        }

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = coordinator
        coordinator.webView = webView

        webView.load(URLRequest(url: url))
        return webView
    }

    func updateWebView(_ webView: WKWebView) {
        guard webView.url != url else { return }
        webView.load(URLRequest(url: url))
    }

    private func loadInterceptorScript() -> String? {
        guard let url = Bundle.main.url(forResource: "Interceptor", withExtension: "js"),
            let script = try? String(contentsOf: url, encoding: .utf8)
        else {
            logError("Failed to load Interceptor.js!")
            return nil
        }
        return script
    }
}

// MARK: - Coordinator

extension WebView {
    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        weak var webView: WKWebView?
        private let handler: WebAuthnHandler

        init(pinHandler: PINRequestHandler) {
            self.handler = WebAuthnHandler { [weak pinHandler] errorMessage in
                await pinHandler?.requestPIN(errorMessage: errorMessage)
            }
        }

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            guard let base64 = message.body as? String,
                let data = Data(base64Encoded: base64)
            else {
                logError("Failed to decode message body")
                return
            }

            Task {
                await handleWebAuthnMessage(name: message.name, data: data)
            }
        }

        @MainActor
        private func handleWebAuthnMessage(name: String, data: Data) async {
            do {
                let response =
                    name == MessageHandler.create
                    ? try await handler.handleCreate(data)
                    : try await handler.handleGet(data)
                let encoded = Data(response.utf8).base64EncodedString()
                _ = try? await webView?.evaluateJavaScript("__webauthn_callback__('\(encoded)')")
            } catch {
                logError("WebAuthn operation failed: \(error)")
                let encoded = Data(error.localizedDescription.utf8).base64EncodedString()
                _ = try? await webView?.evaluateJavaScript("__webauthn_error__('\(encoded)')")
            }
        }
    }
}
