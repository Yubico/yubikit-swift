//
//  AsyncAwaitModel.swift
//  WrapperSample
//
//  Created by Jens Utbult on 2022-12-09.
//

import Foundation
import YubiKit

class AsyncAwaitModel: ObservableObject {
    
    @Published private(set) var status = "No connection"
    
    @MainActor func connect() {
        Task {
            do {
                status = "Trying to connect to YubiKey..."
                let connection = try await ConnectionHelper.anyConnection()
                let session = try await OATHSession.session(withConnection: connection)
                let codes = try await session.calculateCodes()
                session.end()
                if let nfcConnection = connection as? NFCConnection {
                    nfcConnection.close(result: .success("Calculated codes"))
                }
                status = "Got \(codes.count) codes from YubiKey using async/await"
            } catch {
                status = "🧅 Error: \(error)"
            }
        }
    }
}
