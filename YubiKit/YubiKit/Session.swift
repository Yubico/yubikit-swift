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
    func end()
    func sessionDidEnd() async -> Error?
}


internal protocol InternalSession {
    var connection: Connection? { get set }
}

extension InternalSession {
    var internalConnection: InternalConnection? {
        connection as? InternalConnection
    }
}

public enum SessionError: Error {
    case noConnection
    case activeSession
    case missingApplication
    case unexpectedStatusCode
}
