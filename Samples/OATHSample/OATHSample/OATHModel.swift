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

class OATHModel: ObservableObject {
    @Published private(set) var errorMessage: String?
    @Published private(set) var codes = [Code]()
    @Published private(set) var source = "no connection"
    
    private var connectionHandler = ConnectionHandler()
    private var calculateCodesTask: Task<(), Never>?
    
    @MainActor func startLightningConnection() {
        calculateCodes(connectionType: .lightning)
        Task {
            do {
                let connection = try await self.connectionHandler.connection(type: .lightning)
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
    
    @MainActor func simulateYubiKey(insert: Bool) {
        LightningConnection.simulateYubiKey(inserted: insert)
    }
    
    @MainActor func calculateCodes(connectionType: ConnectionHandler.ConnectionType = .lightning) {
        print("await calculateCodes()")
        calculateCodesTask?.cancel()
        calculateCodesTask = Task {
            self.errorMessage = nil
            do {
                let connection = try await self.connectionHandler.connection(type: connectionType)
                print("Got connection in calculateCodes()")
                
                if Task.isCancelled { return }
                let session = try await OATHSession.session(withConnection: connection)
                if Task.isCancelled { return }
                self.codes = try await session.calculateCodes()
                if connectionType == .nfc {
                    session.end(result: nil, closingConnection: true)
                }
                self.source = connectionType == .lightning ? "lightning" : "NFC"
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
