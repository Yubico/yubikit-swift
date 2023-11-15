//
//  ContentView.swift
//  WrapperSample
//
//  Created by Jens Utbult on 2022-12-09.
//

import SwiftUI

struct ContentView: View {
    
    @StateObject var model = AsyncAwaitModel()
    @StateObject var wrapperModel = CallbackWrapperModel()
    @StateObject var delegateWrapperModel = DelegateWrapperModel()
    @State var result = "No connection"
    
    var body: some View {
        VStack {
            Text("🎁").font(.system(size: 100))
            Button {
                model.connect()
            } label: {
                Label("Connect using async/await", systemImage: "arrow.clockwise.circle")
            }.buttonStyle(BlueButtonStyle())
            Button {
                wrapperModel.connect()
            } label: {
                Label("Connect with callback wrapper", systemImage: "arrow.clockwise.circle")
            }.buttonStyle(BlueButtonStyle())
            Button {
                delegateWrapperModel.connect()
            } label: {
                Label("Connect with delegate & callback wrapper", systemImage: "arrow.clockwise.circle")
            }.buttonStyle(BlueButtonStyle())
            Spacer()
            Text(result).multilineTextAlignment(.center)
            Spacer()
        }
        .padding()
        .onChange(of: model.status) {
            result = model.status
        }
        .onChange(of: wrapperModel.status) {
            result = wrapperModel.status
        }
        .onChange(of: delegateWrapperModel.status) {
            result = delegateWrapperModel.status
        }
    }
}

struct BlueButtonStyle: ButtonStyle {
    func makeBody(configuration: Self.Configuration) -> some View {
        configuration.label
            .font(.headline)
            .padding()
            .foregroundColor(configuration.isPressed ? Color.blue : Color.white)
            .background(configuration.isPressed ? Color.white : Color.blue)
            .cornerRadius(10.0)
    }
}

