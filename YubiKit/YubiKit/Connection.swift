//
//  Connection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

public protocol Connection: AnyObject {
    // Waits for a new Connection. Only one call to connection() can be present, if a second call is made the previous
    // awaited Task is cancelled, if a Connection previously has been established and returned it will be closed.
    static func connection() async throws -> Connection
    // Close the current Connection
    func close(signalClosure: Bool, error: Error?) async
    // Returns when the Connection is closed. If this was due to an error said Error is returned.
    func connectionDidClose() async -> Error?
    // Send a APDU to the Connection.
    func send(apdu: APDU) async throws -> Response
}

extension Connection {
    func close(signalClosure: Bool = false, error: Error? = nil) async {
        await close(signalClosure: signalClosure, error: error)
    }
}

internal protocol InternalConnection {
    func session() async -> Session?
    func setSession(_ session: Session?) async
}

extension InternalConnection {
    func internalSession() async -> InternalSession? {
        let internalSession = await session()
        return internalSession as? InternalSession
    }
}

