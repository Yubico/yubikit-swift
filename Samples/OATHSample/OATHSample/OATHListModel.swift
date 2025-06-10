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

    @MainActor func stopWiredConnection() {
        source = "no connection"
        accounts.removeAll()
        wiredConnectionTask?.cancel()
    }

    @MainActor func startWiredConnection() {
        wiredConnectionTask?.cancel()
        wiredConnectionTask = Task {
            do {
                error = nil
                // Wait for a suitable wired connection for the current device.
                let connection = try await ConnectionHelper.anyWiredConnection()
                guard !Task.isCancelled else { return }
                try await self.calculateCodes(connection: connection)
                // Wait for the connection to close, i.e the YubiKey to be unplugged from the device.
                // If the YubiKey was simply unplugged it will return nil, otherwise the error
                // causing the disconnect will be returned.
                self.error = await connection.connectionDidClose()
                self.accounts.removeAll()
                self.source = "no connection"
                guard !Task.isCancelled else { return }
                // Restart the wired connection and go back to waiting for a YubiKey to be
                // inserted again.
                self.startWiredConnection()
            } catch {
                self.error = error
            }
        }
    }

    #if os(iOS)
    @MainActor func calculateNFCCodes() {
        Task {
            // the idea of this change it to make sure, that if an error occured,
            // we call close(error)
            // there must exists better way how to write this in swift
            var connection: Connection? = nil
            do {
                self.error = nil
                connection = try await NFCConnection.connection()
                if (connection != nil) {
                    try await calculateCodes(connection: connection!)
                    await connection!.nfcConnection?.close(message: "Code calculated")
                }
            } catch {
                if (connection != nil) {
                    await connection!.nfcConnection?.close(error: error)
                }
                self.accounts = []
                self.error = error
            }
        }
    }
    #else
    @MainActor func calculateNFCCodes() {}  // do nothing on macOS
    #endif

    @MainActor private func calculateCodes(connection: Connection) async throws {
        self.error = nil
        do {
            let session = try await OATHSession.session(withConnection: connection)
            if (session.isAccessKeySet) {
                // FIPS keys always have a password
                // to simplify we hardcoded here
                try await session.unlockWithPassword("11234567")
            }
            // will ios kill the connection when it takes long time?
            // There are 2 timeouts:
            //   - Session timeout (counted since begin()) which is ~1 minute
            //   - tag timeout (counted since tagReader:didDetect) which is ~20 seconsd :')
            // calculate all code several times using the same connection/session
            try await session.calculateCodes() // sometimes can this line cause a timeout already
            // try await session.calculateCodes() // including this line takes too long on FIPS with 64 SHA512 account
            let result = try await session.calculateCodes()
            self.accounts = result.map { Account(label: $0.0.label, code: $0.1?.code ?? "****") }
            self.source = connection.connectionType
        } catch {
            self.error = error
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
