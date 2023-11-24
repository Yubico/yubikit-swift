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


class OATHListModel: ObservableObject {
    @Published private(set) var accounts = [Account]()
    @Published private(set) var source = "no connection"
    @Published var error: Error?
    
    private var wiredConnectionTask: Task<Void, Never>?
    
    @MainActor func stopWiredConnection() {
        source = "no connection"
        accounts.removeAll()
        wiredConnectionTask?.cancel()
    }
    
    @MainActor func startWiredConnection() {
        print("startWiredConnection()")
        wiredConnectionTask?.cancel()
        wiredConnectionTask = Task {
            do {
                error = nil
                let connection = try await ConnectionHelper.anyWiredConnection()
                guard !Task.isCancelled else { return }
                self.calculateCodes(connection: connection)
                self.error = await connection.connectionDidClose()
                self.accounts.removeAll()
                self.source = "no connection"
                guard !Task.isCancelled else { return }
                self.startWiredConnection()
            } catch {
                self.error = error
            }
        }
    }
    
    #if os(iOS)
    @MainActor func calculateNFCCodes() {
        Task {
            do {
                self.error = nil
                let connection = try await NFCConnection.connection()
                calculateCodes(connection: connection)
                await connection.nfcConnection?.close(message: "Code calculated")
            } catch {
                self.error = error
            }
        }
    }
    #endif
    
    @MainActor private func calculateCodes(connection: Connection) {
        Task {
            self.error = nil
            do {
                let session = try await OATHSession.session(withConnection: connection)
                let result = try await session.calculateCodes()
                self.accounts = result.map { return Account(label: $0.0.label, code: $0.1?.code ?? "****") }
                self.source = connection.connectionType
            } catch {
                self.error = error
            }
        }
    }
}

struct Account: Identifiable {
    var id = UUID()
    let label: String
    let code: String
}

extension Connection {
    var connectionType: String {
        #if os(iOS)
        if self as? NFCConnection != nil {
            return "NFC"
        } else if self as? LightningConnection != nil {
            return "Lightning"
        } else if self as? SmartCardConnection != nil {
            return "SmartCard"
        } else {
            return "Unknown"
        }
        #else
        if self as? SmartCardConnection != nil {
            return "SmartCard"
        } else {
            return "Unknown"
        }
        #endif
    }
}
