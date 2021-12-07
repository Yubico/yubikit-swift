//
//  OATHModel.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation
import YubiKit




// Start lightning immediately, if we get a connection calculate code with it
// If we loose the lightning connection start a new one

// If user pushes nfc button start nfc and calcualte code with connection

class OATHListModel: ObservableObject {
    @Published private(set) var errorMessage: String?
    @Published private(set) var codes = [Code]()
    @Published private(set) var source = "no connection"
    
    private var connectionHandler = ConnectionHandler()
    
    private var lightningConnectionTask: Task<Void, Never>?
    
    @MainActor func simulateYubiKey(insert: Bool) {
        Task {
            await LightningConnection.simulateYubiKey(inserted: insert)
        }
    }
    
    func stopLightningConnection() {
        lightningConnectionTask?.cancel()
    }
    
    @MainActor func startLightningConnection() {
        calculateCodes(connectionType: .lightning)
        lightningConnectionTask?.cancel()
        lightningConnectionTask = Task {
            do {
                let connection = try await self.connectionHandler.connection(type: .lightning)
                if Task.isCancelled { print("task cancelled, bailot"); return }
                print("Got connection in startLigthningConnection()")
                let closingError = try await connection.connectionDidClose()
                print("Lightning closed with error: \(closingError ?? "no error")")
                codes.removeAll()
                source = "no connection"
                self.startLightningConnection()
            } catch {
                print("Lightning connection failed with error: \(error)")
            }
        }
    }
    
    @MainActor func calculateCodes(connectionType: ConnectionHandler.ConnectionType) {
        print("await calculateCodes(\(connectionType))")
        Task {
            self.errorMessage = nil
            do {
                let connection = try await self.connectionHandler.connection(type: connectionType)
                if Task.isCancelled { print("task cancelled, bailot"); return }
                print("Got connection in calculateCodes()")
                let session = try await OATHSession.session(withConnection: connection)
                self.codes = try await session.calculateCodes()
                if connection.type == .nfc {
                    self.source =  "NFC"
                    await session.end(result: nil, closingConnection: true)
                } else {
                    self.source = "lightning"
                }
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
