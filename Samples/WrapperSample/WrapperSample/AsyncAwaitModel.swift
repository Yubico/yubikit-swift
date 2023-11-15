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
            let connection: Connection
            do {
                status = "Trying to connect to YubiKey..."
                connection = try await ConnectionHelper.anyConnection()
                let session = try await OATHSession.session(withConnection: connection)
                let codes = try await session.calculateCodes()
                #if os(iOS)
                await connection.nfcConnection?.close(message: "Calculated codes")
                #endif
                status = "Got \(codes.count) codes from YubiKey using async/await"
            } catch {
                status = "Error: \(error)"
            }
        }
    }
}
