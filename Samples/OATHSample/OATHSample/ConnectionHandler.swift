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
    }

    private weak var nfcConnection: NFCConnection?
    private weak var lightningConnection: LightningConnection?

    func connection(type: ConnectionType = .lightning) async throws -> Connection {
        switch type {
        case .nfc:
            let connection = try await NFCConnection.connection()
            nfcConnection = connection
            return connection
        case .lightning:
            let connection = try await LightningConnection.connection()
            lightningConnection = connection
            return connection
        }
    }
}
