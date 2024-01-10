// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import SwiftUI


struct OATHListView<T>: View where T: OATHListModelProtocol {
    
    @StateObject var model: T
    @State private var isPresentingSettings = false

    var body: some View {
        NavigationStack {
            List(model.accounts) {
                AccountRowView(account: $0)
            }
            .navigationTitle("Codes (\(model.source))")
            .toolbar(content: {
                ToolbarItem() {
                    Button(action: { model.stopWiredConnection(); isPresentingSettings.toggle() }) {
                        Image(systemName: "ellipsis.circle")
                    }
                    .sheet(isPresented: $isPresentingSettings, onDismiss: {
                        model.startWiredConnection() // Restart wired connection once the SettingsView has been dismissed.
                    }, content: {
                        SettingsView(model: SettingsModel())
                    })
                }
            })
            #if os(iOS)
            .refreshable {
                model.calculateNFCCodes()
            }
            #endif
        }
        .onAppear {
            model.startWiredConnection()
        }
        .alert("Something went wrong", isPresented: .constant(model.error != nil), actions: {
            Button("Ok", role: .cancel) { model.startWiredConnection() }
        }, message: {
            if let error = model.error {
                Text("\(String(describing: error))")
            }
        })
    }
}


struct AccountRowView: View {
    let account: Account
    var body: some View {
        HStack {
            Text(account.label)
            Spacer()
            Text(account.code)
        }
    }
}


#Preview {
  OATHListView(model: OATHListModelPreview())
}

class OATHListModelPreview: OATHListModelProtocol {
    @Published private(set) var accounts = [Account(label: "Label 1", code: "123456"),
                                            Account(label: "Label 2", code: "123456"),
                                            Account(label: "Label 3", code: "123456")]
    @Published private(set) var source = "no connection"
    @Published var error: Error?
    
    func stopWiredConnection() {}
    func startWiredConnection() {}
    func calculateNFCCodes() {}
}
