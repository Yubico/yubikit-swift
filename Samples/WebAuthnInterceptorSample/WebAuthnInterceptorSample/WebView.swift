//
//  WebView.swift
//  WebAuthnInterceptorSample
//

import SwiftUI
import WebKit

// MARK: - Navigator

@MainActor
class WebViewNavigator: ObservableObject {
    weak var webView: WKWebView? {
        didSet { setupObservation() }
    }

    @Published var canGoBack = false
    private var observation: NSKeyValueObservation?

    func goBack() {
        webView?.goBack()
    }

    private func setupObservation() {
        observation = webView?.observe(\.canGoBack, options: [.initial, .new]) { [weak self] webView, _ in
            Task { @MainActor in
                self?.canGoBack = webView.canGoBack
            }
        }
    }
}

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

// MARK: - Shared Implementation

private let messageHandlerNames = ["__webauthn_create__", "__webauthn_get__"]

extension WebView {
    static func cleanupWebView(_ webView: WKWebView) {
        trace("Cleaning up WebView message handlers")
        let controller = webView.configuration.userContentController
        for name in messageHandlerNames {
            controller.removeScriptMessageHandler(forName: name)
        }
    }

    func createWebView(context: Context) -> WKWebView {
        trace("Creating WebView...")
        let config = WKWebViewConfiguration()
        let coordinator = context.coordinator

        if let interceptorScript = loadInterceptorScript() {
            let script = WKUserScript(
                source: interceptorScript,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
            config.userContentController.addUserScript(script)
            trace("Interceptor.js injected")
        }

        for name in messageHandlerNames {
            config.userContentController.add(coordinator, name: name)
        }
        trace("Message handlers registered")

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = coordinator
        coordinator.webView = webView

        trace("Loading URL: \(url.absoluteString)")
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
            trace("Failed to load Interceptor.js!")
            return nil
        }
        return script
    }
}

// MARK: - Coordinator

extension WebView {
    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        weak var webView: WKWebView?
        private let bridgeModel: Bridge

        init(pinHandler: PINRequestHandler) {
            self.bridgeModel = Bridge { [weak pinHandler] errorMessage in
                await pinHandler?.requestPIN(errorMessage: errorMessage)
            }
        }

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            trace("Received message: \(message.name)")

            guard let body = message.body as? String,
                let data = body.data(using: .utf8)
            else {
                trace("Failed to parse message body")
                return
            }

            trace("Message body: \(body)")

            Task {
                await handleWebAuthnMessage(name: message.name, data: data)
            }
        }

        @MainActor
        private func handleWebAuthnMessage(name: String, data: Data) async {
            do {
                let response: String
                if name == "__webauthn_create__" {
                    trace("Dispatching to handleCreate")
                    response = try await bridgeModel.handleCreate(data)
                } else {
                    trace("Dispatching to handleGet")
                    response = try await bridgeModel.handleGet(data)
                }

                trace("Operation succeeded, executing JS callback")
                let js = "__webauthn_callback__('\(response.escapedForJavaScript())')"
                _ = try? await webView?.evaluateJavaScript(js)
            } catch {
                trace("Operation failed: \(error) (\(type(of: error)))")
                let js = "__webauthn_error__('\(error.localizedDescription.escapedForJavaScript())')"
                _ = try? await webView?.evaluateJavaScript(js)
            }
        }
    }
}

// MARK: - String Escaping

extension String {
    fileprivate func escapedForJavaScript() -> String {
        self.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\t", with: "\\t")
    }
}
