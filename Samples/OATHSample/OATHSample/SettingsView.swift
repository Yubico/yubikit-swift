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

struct SettingsView<T>: View where T: SettingsModelProtocol {
    
    @Environment(\.dismiss) var dismiss
    @StateObject var model: T
    
    var body: some View {
        Text("\(model.connection ?? "Unknown") YubiKey, \(model.keyVersion ?? "Unknown version")")
            .frame(width: 300)
            .padding()
        Button {
            dismiss()
        } label: {
            Text("Dismiss")
        }
        .padding()
        .alert("Something went wrong", isPresented: .constant(model.error != nil), actions: {
            Button("Ok", role: .cancel) { dismiss() }
        }, message: {
            if let error = model.error {
                Text("\(String(describing: error))")
            }
        })
        .onAppear {
            model.getKeyVersion()
        }
    }
    
}


#Preview {
    SettingsView(model: SettingsModelPreview())
}

class SettingsModelPreview: SettingsModelProtocol {
    @Published private(set) var keyVersion: String? = "5.4.2"
    @Published private(set) var connection: String? = "SmartCard"
    @Published private(set) var error: Error?
    @MainActor func getKeyVersion() {}
}
