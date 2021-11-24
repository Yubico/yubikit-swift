//
//  ContentView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-11.
//

import SwiftUI



struct ContentView: View {
    
    @StateObject var model = OATHModel()
    
    var body: some View {
        NavigationView {
            List(model.codes) {
                Text($0.code)
            }
            .navigationTitle("Codes (\(model.source))")
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
        ContentView()
    }
}
