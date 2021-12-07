//
//  ConnectionHandler.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-18.
//

import Foundation
import YubiKit

class ConnectionHandler {
    
    enum ConnectionType {
        case nfc
        case lightning
        case any
    }
    
    func connection(type: ConnectionType = .any) async throws -> Connection {
        switch type {
        case .nfc:
            return try await NFCConnection.connection()
        case .lightning:
            return try await LightningConnection.connection()
        case .any:
            return try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
                group.addTask {
                    await Task.sleep(1_000_000_000 * UInt64(1.0)) // wait for lightning to connect for 1 second
                    try Task.checkCancellation()
                    return try await NFCConnection.connection()
                }
                group.addTask {
                    return try await LightningConnection.connection()
                }
                let result = try await group.next()!
                group.cancelAll()
                return result
            }
        }
    }
}

extension Connection {
    var type: ConnectionHandler.ConnectionType {
        return self as? NFCConnection != nil ? .nfc : .lightning
    }
}
