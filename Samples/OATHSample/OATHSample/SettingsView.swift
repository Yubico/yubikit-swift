//
//  SettingsView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-24.
//

import SwiftUI

struct SettingsView: View {
    @StateObject var model = SettingsModel()
    
    var body: some View {
        Text("\(model.connection ?? "Unknown") key, version: \(model.keyVersion ?? "?")")
            .onAppear {
                model.getKeyVersion()
            }
    }
    
}

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        SettingsView()
    }
}
