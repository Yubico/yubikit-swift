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
import YubiKit

struct SettingsView: View {

    @Environment(\.dismiss) var dismiss
    @StateObject var model: Model
    @StateObject private var connectionManager = ConnectionManager.shared

    var body: some View {
        VStack(spacing: 20) {
            Capsule()
                .fill(Color.secondary.opacity(0.4))
                .frame(width: 40, height: 5)
                .padding(.top, 10)

            Text("YubiKey Information")
                .font(.headline)
                .padding(.top, 10)

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Connection:")
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(model.connectionType ?? "Unknown")
                        .fontWeight(.medium)
                }

                HStack {
                    Text("Version:")
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(model.keyVersion ?? "Unknown")
                        .fontWeight(.medium)
                }
            }
            .padding(.horizontal, 20)
            .frame(maxWidth: .infinity)

            Spacer()

            Button(action: { dismiss() }) {
                Text("Done").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .presentationDetents([.fraction(0.5)])
        .presentationDragIndicator(.hidden)
        #if os(iOS)
        .refreshable {
            await connectionManager.requestNFCConnection()
        }
        #endif
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.error != nil },
                set: { _ in model.error = nil }
            ),
            actions: {
                Button("Ok", role: .cancel) {}
            },
            message: {
                if let error = model.error {
                    Text("\(String(describing: error))")
                }
            }
        )
    }
}
