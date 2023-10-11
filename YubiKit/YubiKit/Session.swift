//
//  Session.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

extension String: Error {}

public protocol Session: AnyObject {
    static func session(withConnection connection: Connection) async throws -> Self
    func end() async
    func sessionDidEnd() async -> Error?
}

internal protocol InternalSession {
    func connection() async -> Connection?
    func setConnection(_ connection: Connection?) async
}

extension InternalSession {
    func internalConnection() async -> InternalConnection? {
        let connection = await connection()
        return connection as? InternalConnection
    }
}

public enum SessionError: Error {
    case noConnection
    case activeSession
    case missingApplication
    case unexpectedStatusCode
}
