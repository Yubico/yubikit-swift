//
//  Connection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

public protocol Connection: AnyObject {
    static func connection() async throws -> Connection
    func close(result: Result<String, Error>?) async
    func connectionDidClose() async -> Error?
    func send(apdu: APDU) async throws -> Data
}


internal protocol InternalConnection {
    var session: Session? { get set }
}

extension InternalConnection {
    var internalSession: InternalSession? {
        session as? InternalSession
    }
}

