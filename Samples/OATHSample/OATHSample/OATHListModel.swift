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
    
    private var wiredConnectionTask: Task<Void, Never>?
    
    @MainActor func simulateYubiKey(insert: Bool) {
        #if os(iOS)
        Task {
            await LightningConnection.simulateYubiKey(inserted: insert)
        }
        #endif
    }
    
    func stopWiredConnection() {
        wiredConnectionTask?.cancel()
    }
    
    @MainActor func startWiredConnection() {
        print("startWiredConnection()")
        #if os(iOS)
        calculateCodes(connectionType: .lightning)
        #else
        calculateCodes(connectionType: .smartCard)
        #endif
        
        wiredConnectionTask?.cancel()
        wiredConnectionTask = Task {
            do {
                #if os(iOS)
                let connection = try await self.connectionHandler.connection(type: .lightning)
                #else
                let connection = try await self.connectionHandler.connection(type: .smartCard)
                #endif
                if Task.isCancelled { print("Task cancelled, bailot"); return }
                print("Got connection in startWiredConnection(), lets wait for it to close...")
                let closingError = await connection.connectionDidClose()
                print("Wired connection closed with error: \(closingError ?? "no error")")
                codes.removeAll()
                source = "no connection"
                self.startWiredConnection()
            } catch {
                print("Wired connection failed with error: \(error)")
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
                #if os(iOS)
                if connection.type == .nfc {
                    self.source =  "NFC"
                    await session.end(withConnectionStatus: .close(.success("Calculated codes")))
                } else {
                    self.source = "lightning"
                }
                #else
                self.source = "smart card"
                #endif
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
