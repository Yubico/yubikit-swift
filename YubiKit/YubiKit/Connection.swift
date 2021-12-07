//
//  Connection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

public protocol Connection: AnyObject {
    static func connection() async throws -> Self
    var smartCardInterface: SmartCardInterface { get }
    func close(_: Result<String, Error>?) async
    func connectionDidClose() async throws -> Error?
}


internal protocol InternalConnection {
    func sendAPDU() async throws -> Result<Data, Error>
    var session: Session? { get set }
}

extension InternalConnection {
    var internalSession: InternalSession? {
        session as? InternalSession
    }
}

