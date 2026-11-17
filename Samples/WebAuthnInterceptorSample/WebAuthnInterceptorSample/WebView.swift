import SwiftUI
import WebKit
import YubiKit

private func log(_ message: String) {
    print("[WebAuthn] \(message)")
}

private enum WebAuthnMessage: String, CaseIterable {
    case create = "__webauthn_create__"
    case get = "__webauthn_get__"
    case console = "__webauthn_console__"
}

@MainActor
final class WebViewNavigator {
    fileprivate weak var webView: WKWebView?

    func goBack() {
        webView?.goBack()
    }
}

#if os(iOS)
struct WebView: UIViewRepresentable {
    let url: URL
    let navigator: WebViewNavigator

    func makeUIView(context: Context) -> WKWebView {
        let webView = createWebView(context: context)
        navigator.webView = webView
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        updateWebView(webView)
    }

    static func dismantleUIView(
        _ webView: WKWebView,
        coordinator: Coordinator
    ) {
        MainActor.assumeIsolated { coordinator.shutdown() }
        cleanupWebView(webView)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }
}
#else
struct WebView: NSViewRepresentable {
    let url: URL
    let navigator: WebViewNavigator

    func makeNSView(context: Context) -> WKWebView {
        let webView = createWebView(context: context)
        navigator.webView = webView
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        updateWebView(webView)
    }

    static func dismantleNSView(
        _ webView: WKWebView,
        coordinator: Coordinator
    ) {
        MainActor.assumeIsolated { coordinator.shutdown() }
        cleanupWebView(webView)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }
}
#endif

extension WebView {
    private static func cleanupWebView(_ webView: WKWebView) {
        let controller = webView.configuration.userContentController
        for message in WebAuthnMessage.allCases {
            controller.removeScriptMessageHandler(forName: message.rawValue)
        }
    }

    private func createWebView(context: Context) -> WKWebView {
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

        for message in WebAuthnMessage.allCases {
            config.userContentController.add(
                coordinator,
                name: message.rawValue
            )
        }

        let webView = WKWebView(frame: .zero, configuration: config)
        if #available(macOS 13.3, iOS 16.4, *) {
            webView.isInspectable = true
        }
        webView.navigationDelegate = coordinator
        coordinator.webView = webView

        webView.load(URLRequest(url: url))
        return webView
    }

    private func updateWebView(_ webView: WKWebView) {
        guard webView.url != url else { return }
        webView.load(URLRequest(url: url))
    }

    private func loadInterceptorScript() -> String? {
        guard
            let url = Bundle.main.url(
                forResource: "Interceptor",
                withExtension: "js"
            ),
            let script = try? String(contentsOf: url, encoding: .utf8)
        else {
            log("Failed to load Interceptor.js!")
            return nil
        }
        return script
    }
}

extension WebView {
    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate,
        WKScriptMessageHandler
    {
        fileprivate weak var webView: WKWebView?
        private lazy var handler = WebAuthnHandler(presentationAnchor: { [weak self] in self?.webView?.window })
        private var activeTask: Task<Void, Never>?
        private var ceremonyGeneration: UInt64 = 0

        /// Release the ceremony and transport when the host view is removed.
        fileprivate func shutdown() {
            activeTask?.cancel()
            activeTask = nil
            let handler = self.handler
            Task { await handler.cancelActiveCeremony() }
        }

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            if message.name == WebAuthnMessage.console.rawValue {
                log("JS: \(message.body)")
                return
            }

            guard message.frameInfo.isMainFrame else { return }

            let frameOrigin = message.frameInfo.securityOrigin
            var components = URLComponents()
            components.scheme = frameOrigin.protocol
            components.host = frameOrigin.host
            if frameOrigin.port > 0,
                !(frameOrigin.protocol == "https" && frameOrigin.port == 443),
                !(frameOrigin.protocol == "http" && frameOrigin.port == 80)
            {
                components.port = frameOrigin.port
            }
            guard let originURL = components.url,
                let origin = try? WebAuthn.Origin(originURL)
            else {
                let error = Data("Invalid or insecure origin".utf8).base64EncodedString()
                Task { _ = try? await webView?.evaluateJavaScript("__webauthn_error__('\(error)')") }
                return
            }
            guard let body = message.body as? String else {
                log("Invalid message body")
                return
            }
            let data = Data(body.utf8)

            ceremonyGeneration += 1
            let generation = ceremonyGeneration
            activeTask?.cancel()
            activeTask = Task {
                await handler.cancelActiveCeremony()
                await handleWebAuthnMessage(
                    name: message.name,
                    data: data,
                    origin: origin,
                    generation: generation
                )
            }
        }

        @MainActor
        private func handleWebAuthnMessage(
            name: String,
            data: Data,
            origin: WebAuthn.Origin,
            generation: UInt64
        ) async {
            guard let message = WebAuthnMessage(rawValue: name) else {
                return
            }
            do {
                let response: String
                switch message {
                case .create:
                    response = try await handler.handleCreate(data, origin: origin)
                case .get:
                    response = try await handler.handleGet(data, origin: origin)
                case .console:
                    return
                }
                guard generation == ceremonyGeneration else { return }
                let encodedResponse = Data(response.utf8)
                    .base64EncodedString()
                _ = try? await webView?.evaluateJavaScript(
                    "__webauthn_callback__('\(encodedResponse)')"
                )
            } catch {
                guard generation == ceremonyGeneration else { return }
                log("WebAuthn operation failed: \(error)")
                let encodedError = Data(
                    error.localizedDescription.utf8
                ).base64EncodedString()
                _ = try? await webView?.evaluateJavaScript(
                    "__webauthn_error__('\(encodedError)')"
                )
            }
        }
    }
}
