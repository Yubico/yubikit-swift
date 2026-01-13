//
//  ContentView.swift
//  WebAuthnInterceptorSample
//

import SwiftUI

struct ContentView: View {
    private static let defaultURLString = "https://demo.yubico.com/webauthn-developers"

    @State private var urlString = defaultURLString
    @State private var currentURL = URL(string: defaultURLString)!
    @StateObject private var pinHandler = PINRequestHandler()
    @StateObject private var navigator = WebViewNavigator()

    var body: some View {
        VStack(spacing: 0) {
            urlBar
            WebView(url: currentURL, pinHandler: pinHandler, navigator: navigator)
        }
        .sheet(isPresented: $pinHandler.isShowingPINEntry) {
            PINEntryView(
                onSubmit: pinHandler.submitPIN,
                onCancel: pinHandler.cancel,
                errorMessage: pinHandler.errorMessage
            )
        }
    }

    private var urlBar: some View {
        HStack {
            Button(action: navigator.goBack) {
                Image(systemName: "chevron.left")
            }
            .disabled(!navigator.canGoBack)

            TextField("URL", text: $urlString)
                .textFieldStyle(.roundedBorder)
                #if os(iOS)
            .textInputAutocapitalization(.never)
                #endif
                .disableAutocorrection(true)
                .onSubmit(navigate)

            Button("Go", action: navigate)
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private func navigate() {
        let hasScheme = urlString.hasPrefix("http://") || urlString.hasPrefix("https://")
        let urlWithScheme = hasScheme ? urlString : "https://" + urlString
        guard let url = URL(string: urlWithScheme) else { return }
        currentURL = url
    }
}

#Preview {
    ContentView()
}
