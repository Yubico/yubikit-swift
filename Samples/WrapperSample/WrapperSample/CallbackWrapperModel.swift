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

class CallbackWrapperModel: ObservableObject {
    
    @Published private(set) var status = "No connection"
    
    @MainActor func connect() {
        
        status = "Trying to connect to YubiKey..."
        
        ConnectionHelper.anyConnection() { connection, error in
            guard let connection else {
                self.status = "Error: \(error!)"
                return
            }
            OATHSession.session(withConnection: connection) { session, error in
                guard let session = session as? OATHSession else {
                    connection.close(error: error!) { }
                    self.status = "Error: \(error!)"
                    return
                }
                session.calculateCodes { codes, error in
                    guard let codes else {
                        self.status = "Error: \(error!)"
                        return
                    }
                    self.status = "Got \(codes.count) codes from YubiKey using callback wrapper"
                    #if os(iOS)
                    connection.closeIfNFC(message: "Calculated codes") { print("Closed") }
                    #endif
                }
            }
        }
    }
}
