//
//  ContentView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-11.
//

import SwiftUI


struct OATHListView: View {
    
    @StateObject var model = OATHListModel()
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
                        model.startWiredConnection()
                    }, content: {
                        SettingsView()
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
