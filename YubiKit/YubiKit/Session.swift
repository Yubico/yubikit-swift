//
//  Session.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

/// An interface defining a session with a specific application on the YubiKey.
///
/// The Session uses a ``Connection`` to handle communication with the YubiKey. Using a session is the preferred way
/// of communicating with the different applications on the YubiKey.
///
/// The protocol is implemented by ``OATHSession`` and ``ManagementSession``.
public protocol Session: AnyObject {
    
    /// Returns a new session using the supplied connection.
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
