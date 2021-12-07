//
//  Session.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

extension String: Error {}

public enum ConnectionStatus {
    case close(Result<String, Error>?)
    case leaveOpen
}

public protocol Session: AnyObject {
    static func session(withConnection connection: Connection) async throws -> Self
    func end(withConnectionStatus: ConnectionStatus) async
    func sessionDidEnd() async throws -> Error?
}


internal protocol InternalSession {
    var connection: Connection? { get }
}

extension InternalSession {
    var internalConnection: InternalConnection {
        get {
            // If the connection is not an InternalConnection we should crash
            connection as! InternalConnection
        }
    }
}
