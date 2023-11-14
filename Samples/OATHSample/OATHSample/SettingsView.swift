//
//  SettingsView.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-24.
//

import SwiftUI

struct SettingsView: View {
    
    @Environment(\.dismiss) var dismiss
    @StateObject var model = SettingsModel()
    
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

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        SettingsView()
    }
}
