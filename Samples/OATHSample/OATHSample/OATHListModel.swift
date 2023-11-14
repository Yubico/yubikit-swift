//
//  OATHModel.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-16.
//

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
    
    @MainActor func calculateNFCCodes() {
        Task {
            do {
                self.error = nil
                let connection = try await NFCConnection.connection()
                calculateCodes(connection: connection)
            } catch {
                self.error = error
            }
        }
    }
    
    @MainActor private func calculateCodes(connection: Connection) {
        Task {
            self.error = nil
            do {
                let session = try await OATHSession.session(withConnection: connection)
                let result = try await session.calculateCodes()
                self.accounts = result.map { return Account(label: $0.0.label, code: $0.1?.code ?? "****") }
                self.source = connection.connectionType
                #if os(iOS)
                await connection.nfcConnection?.close(message: "Code calculated")
                #endif
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
