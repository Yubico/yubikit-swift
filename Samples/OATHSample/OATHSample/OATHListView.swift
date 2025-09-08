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

struct OATHListView: View {

    @StateObject var model = Model()
    @StateObject private var connectionManager = ConnectionManager.shared
    @State private var isPresentingSettings = false

    var title: String {
        guard let connectionType = model.connectionType else {
            #if os(iOS)
            return "Plug in or scan"
            #else
            return "Connect YubiKey"
            #endif
        }

        return "\(connectionType) Codes"
    }

    var body: some View {
        #if os(iOS)
        let connectionTitle: String = "Tap to scan with NFC or connect via USB/Lightning"
        #else
        let connectionTitle: String = "Connect via USB"
        #endif

        NavigationStack {
            List {
                if model.accounts.isEmpty {
                    VStack(spacing: 20) {
                        Image(systemName: model.connectionType == nil ? "key.icloud" : "key.slash")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)

                        Text(model.connectionType == nil ? "Connect Your YubiKey" : "No Accounts Found")
                            .font(.title2)
                            .fontWeight(.semibold)

                        Text(
                            model.connectionType == nil
                                ? connectionTitle : "Add accounts to your YubiKey to see them here"
                        )
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 20)

                        #if os(iOS)
                        if model.connectionType == nil {
                            Button(action: {
                                Task {
                                    await connectionManager.requestNFCConnection()
                                }
                            }) {
                                Label("Scan with NFC", systemImage: "wave.3.right")
                                    .padding(.horizontal, 20)
                                    .padding(.vertical, 12)
                                    .background(Color.accentColor)
                                    .foregroundColor(.white)
                                    .cornerRadius(10)
                            }
                            .padding(.top, 10)
                        }
                        #endif
                    }
                    .frame(maxWidth: .infinity, minHeight: 400)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                } else {
                    ForEach(model.accounts) { account in
                        AccountRowView(account: account)
                    }
                }
            }
            .navigationTitle(title)
            .toolbar(content: {
                ToolbarItem {
                    Button(action: {
                        isPresentingSettings.toggle()
                    }) {
                        Image(systemName: "info.circle")
                    }
                    .disabled(model.connectionType == nil)
                    .sheet(
                        isPresented: $isPresentingSettings,
                        onDismiss: {},
                        content: { SettingsView(model: model) }
                    )
                }
            })
            #if os(iOS)
            .refreshable {
                await connectionManager.requestNFCConnection()
            }
            #endif
        }
        #if os(iOS)
        .onReceive(connectionManager.$nfcConnection) { newConnection in
            guard let connection = newConnection else {
                return
            }

            Task {
                await model.update(using: connection)
                await connection.close(message: "Codes calculated")
            }
        }
        #endif
        .onReceive(connectionManager.$wiredConnection) { newConnection in
            guard let connection = newConnection else {
                model.clear()
                return
            }

            Task { await model.update(using: connection) }
        }
        .onReceive(connectionManager.$error) { error in
            switch error {
            case .some(ConnectionError.cancelledByUser):
                return
            default:
                model.error = error
            }
        }
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

struct AccountRowView: View {
    let account: Account

    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text(account.label)
                    .font(.body)
                if let issuer = account.issuer, !issuer.isEmpty {
                    Text(issuer)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            if let code = account.code {
                Text(code)
                    .font(.system(.title3, design: .monospaced))
            } else {
                Image(systemName: "lock.fill")
                    .font(.body)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
