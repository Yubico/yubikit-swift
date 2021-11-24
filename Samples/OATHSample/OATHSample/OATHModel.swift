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
                let connection = try await connectionHandler.connection(type: .lightning)
                let closingError = try await connection.connectionDidClose()
                print("Lightning closed with error: \(closingError ?? "no error")")
                startLightningConnection()
            } catch {
                print("Lightning failed with error: \(error)")
            }
        }
    }
    
    @MainActor func calculateCodes(connectionType: ConnectionHandler.ConnectionType = .lightning) {
       calculateCodesTask?.cancel()
       calculateCodesTask = Task {
            errorMessage = nil
            do {
                let connection = try await connectionHandler.connection(type: connectionType)
                if Task.isCancelled { return }
                let session = try await OATHSession.session(withConnection: connection)
                if Task.isCancelled { return }
                codes = try await session.calculateCodes()
                source = connectionType == .lightning ? "lightning" : "NFC"
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
