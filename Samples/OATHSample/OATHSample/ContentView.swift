//
//  ContentView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-11.
//

import SwiftUI
import YubiKit

struct ContentView: View {
    
    @StateObject var model = OATHModel()

    var body: some View {
        
        VStack {
            Button {
                model.calculateCode()
            } label: {
                Text("Calculate code")
            }
            Text(model.code)
        }
        .onAppear {
            model.calculateCode()
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
