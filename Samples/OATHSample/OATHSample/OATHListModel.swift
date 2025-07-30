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

protocol OATHListModelProtocol: ObservableObject {
    var accounts: [Account] { get }
    var source: String { get }
    var error: Error? { get }
    func stopWiredConnection()
    func startWiredConnection()
    func calculateNFCCodes()
}

class OATHListModel: OATHListModelProtocol {
    @Published private(set) var accounts = [Account]()
    @Published private(set) var source = "no connection"
    @Published var error: Error?

    private var wiredConnectionTask: Task<Void, Never>?

    func stopWiredConnection() {
        wiredConnectionTask?.cancel()
        wiredConnectionTask = nil
    }

    func startWiredConnection() {
        wiredConnectionTask?.cancel()
        wiredConnectionTask = Task { @MainActor in
            while true {
                do {
                    error = nil
                    guard !Task.isCancelled else { return }
                    // Wait for a suitable wired connection for the current device.
                    let connection = try await WiredSmartCardConnection.connection()
                    guard !Task.isCancelled else { return }
                    try await calculateCodes(connection: connection)
                    // Wait for the connection to close, i.e the YubiKey to be unplugged from the device.
                    // If the YubiKey was simply unplugged it will return nil, otherwise the error
                    // causing the disconnect will be returned.
                    guard !Task.isCancelled else { return }
                    error = await connection.connectionDidClose()
                    accounts.removeAll()
                    source = "no connection"
                    continue
                } catch (let e) {
                    error = e
                    continue
                }
            }
        }
    }

    #if os(iOS)
    func calculateNFCCodes() {
        Task { @MainActor in
            do {
                self.error = nil
                let connection = try await NFCSmartCardConnection.connection()
                try await calculateCodes(connection: connection)
                await connection.nfcConnection?.close(message: "Code calculated")
            } catch {
                self.error = error
            }
        }
    }
    #else
    func calculateNFCCodes() {}  // do nothing on macOS
    #endif

    @MainActor private func calculateCodes(connection: SmartCardConnection) async throws {
        self.error = nil
        let session = try await OATHSession.session(withConnection: connection)
        let result = try await session.calculateCodes()
        self.accounts = result.map { Account(label: $0.0.label, code: $0.1?.code ?? "****") }
        self.source = connection.connectionType
    }
}

struct Account: Identifiable {
    var id = UUID()
    let label: String
    let code: String
}

extension SmartCardConnection {
    var connectionType: String {
        #if os(iOS)
        if self as? NFCSmartCardConnection != nil {
            return "NFC"
        } else if self as? LightningSmartCardConnection != nil {
            return "Lightning"
        } else if self as? USBSmartCardConnection != nil {
            return "SmartCard"
        } else {
            return "Unknown"
        }
        #else
        if self as? USBSmartCardConnection != nil {
            return "SmartCard"
        } else {
            return "Unknown"
        }
        #endif
    }
}
