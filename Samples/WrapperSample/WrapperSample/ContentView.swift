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

