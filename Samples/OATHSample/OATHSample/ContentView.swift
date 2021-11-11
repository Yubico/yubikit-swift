//
//  ContentView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-11.
//

import SwiftUI
import YubiKit

struct ContentView: View {
    var body: some View {
        Text("Roll that dice: \(Dice().roll())!")
            .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
