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
        #if os(iOS)
        case nfc
        case lightning
        #else
        case smartCard
        #endif
        case any
    }
    
    func connection(type: ConnectionType = .any) async throws -> Connection {
        #if os(iOS)
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
                group.addTask {
                    return try await SmartCardConnection.connection()
                }
                let result = try await group.next()!
                group.cancelAll()
                return result
            }
        }
        #else
        return try await SmartCardConnection.connection()
        #endif
    }
}

extension Connection {
    var type: ConnectionHandler.ConnectionType {
        #if os(iOS)
        if self as? NFCConnection != nil { return .nfc }
        if self as? LightningConnection != nil { return .lightning }
        #else
        if self as? SmartCardConnection != nil { return .smartCard }
        #endif
        return .any
    }
}
