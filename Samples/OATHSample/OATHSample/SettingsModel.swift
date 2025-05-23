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

protocol SettingsModelProtocol: ObservableObject {
    var keyVersion: String? { get }
    var connection: String? { get }
    var error: Error? { get }
    func getKeyVersion()
}

class SettingsModel: SettingsModelProtocol {

    @Published private(set) var keyVersion: String?
    @Published private(set) var connection: String?
    @Published private(set) var error: Error?

    @MainActor func getKeyVersion() {
        Task {
            self.error = nil
            do {
                let connection = try await ConnectionHelper.anyConnection()
                let session = try await ManagementSession.session(withConnection: connection)
                self.keyVersion = session.version.description
                #if os(iOS)
                if let nfcConnection = connection.nfcConnection {
                    self.connection = "NFC"
                    await nfcConnection.close(message: "YubiKey version read")
                } else {
                    self.connection = connection as? SmartCardConnection != nil ? "SmartCard" : "Lightning"
                }
                #else
                self.connection = "SmartCard"
                #endif
            } catch {
                self.error = error
            }
        }
    }
}
