//
//  ContentView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-11.
//

import SwiftUI



struct OATHListView: View {
    
    @StateObject var model = OATHListModel()
    @State private var isShowingSettings = false
    @State private var isKeyInserted = false

    var body: some View {
        NavigationView {
            List(model.codes) {
                Text($0.code)
            }
            .navigationTitle("Codes (\(model.source))")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button( "\(isKeyInserted ? "Remove YubiKey" : "Insert YubiKey")") {
                        isKeyInserted.toggle()
                        model.simulateYubiKey(insert: isKeyInserted)
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { model.stopLightningConnection(); isShowingSettings.toggle() }) {
                        Image(systemName: "ellipsis.circle")
                    }
                    .sheet(isPresented: $isShowingSettings, onDismiss: {
                        model.startLightningConnection()
                    }, content: {
                        SettingsView()
                    })
//                    .sheet(isPresented: $isShowingSettings) {

//                    }
                }
            }
            .refreshable {
                model.calculateCodes(connectionType: .nfc)
            }
        }
        .onAppear {
            model.startLightningConnection()
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        OATHListView()
    }
}
