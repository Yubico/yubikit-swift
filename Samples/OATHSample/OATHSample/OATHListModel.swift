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
    @Published private(set) var codes = [OATHSession.Code]()
    @Published private(set) var source = "no connection"
    
    private var wiredConnectionTask: Task<Void, Never>?
    
    func stopWiredConnection() {
        wiredConnectionTask?.cancel()
    }
    
    @MainActor func startWiredConnection() {
        print("startWiredConnection()")
        calculateCodes(useWiredConnection: true)

        wiredConnectionTask?.cancel()
        wiredConnectionTask = Task {
            do {
                let connection = try await ConnectionHelper.anyWiredConnection()
                if Task.isCancelled { print("Task cancelled, bailot"); return }
                print("Got connection in startWiredConnection(), lets wait for it to close...")
                let closingError = await connection.connectionDidClose()
                print("Wired connection closed with error: \(closingError ?? "no error")")
                codes.removeAll()
                source = "no connection"
                guard !Task.isCancelled else { return }
                self.startWiredConnection()
            } catch {
                print("Wired connection failed with error: \(error)")
            }
        }
    }
    
    @MainActor func calculateCodes(useWiredConnection: Bool = false) {
        print("await calculateCodes()")
        Task {
            self.errorMessage = nil
            do {
                #if os(iOS)
                let connection = useWiredConnection ? try await ConnectionHelper.anyWiredConnection() : try await NFCConnection.connection()
                #else
                // Always use wired connection on macOS
                let connection = try await ConnectionHelper.anyConnection()
                #endif

                print("Got connection in calculateCodes()")
                let session = try await OATHSession.session(withConnection: connection)
                print("Got session in calculateCodes()")
                let result = try await session.calculateCodes()
                print("Got result \(result) in calculateCodes()")
                self.codes = result.map { return $0.1 }.compactMap { $0 }
                print("self.codes: \(self.codes)")
                #if os(iOS)
                if connection as? NFCConnection != nil {
                    self.source =  "NFC"
                    await session.end(withConnectionStatus: .close(.success("Calculated codes")))
                } else {
                    self.source = connection as? SmartCardConnection != nil ? "SmartCard" : "lightning"
                }
                #else
                self.source = "SmartCard"
                #endif
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
