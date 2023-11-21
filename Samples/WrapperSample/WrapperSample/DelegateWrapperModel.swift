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

import Foundation
import YubiKit

class DelegateWrapperModel: ObservableObject, YubiKitWrapperDelegate {

    @Published private(set) var status = "No connection"
    let yubikit = YubiKitWrapper()

    init() {
        yubikit.delegate = self
    }
    
    @MainActor func connect() {
        status = "Trying to connect to YubiKey..."
        yubikit.startAnyConnection()
    }
    
    func didConnect(connection: YubiKit.Connection) {
        OATHSession.session(withConnection: connection) { session, error in
            guard let session = session as? OATHSession else {
                self.status = "Error: \(error!)"
                return
            }
            session.calculateCodes { codes, error in
                if let error {
                    self.status = "Error: \(error)"
                    connection.close(error: error) {
                        print("Connection closed with error: \(error)")
                    }
                    return
                }
                guard let codes else { fatalError() }
                self.status = "Got \(codes.count) codes from YubiKey using delegate & callback wrapper"
                #if os(iOS)
                connection.closeIfNFC(message: "Calculated codes") { print("Calculated \(codes.count) codes") }
                #endif
            }
        }
    }
}
