import SwiftUI

struct ContentView: View {
    private static let defaultURLString = "https://demo.yubico.com/webauthn-developers"

    @State private var urlString = defaultURLString
    @State private var currentURL = URL(string: defaultURLString)!
    @State private var navigator = WebViewNavigator()

    var body: some View {
        VStack(spacing: 0) {
            urlBar
            WebView(url: currentURL, navigator: navigator)
        }
    }

    private var urlBar: some View {
        HStack {
            Button(action: navigator.goBack) {
                Image(systemName: "chevron.left")
            }

            TextField("URL", text: $urlString)
                .textFieldStyle(.roundedBorder)
                #if os(iOS)
            .textInputAutocapitalization(.never)
                #endif
                .autocorrectionDisabled()
                .onSubmit(navigate)

            Button("Go", action: navigate)
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private func navigate() {
        let hasScheme =
            urlString.hasPrefix("http://")
            || urlString.hasPrefix("https://")
        let urlWithScheme = hasScheme ? urlString : "https://" + urlString
        guard let url = URL(string: urlWithScheme) else { return }
        currentURL = url
    }
}

#Preview {
    ContentView()
}
