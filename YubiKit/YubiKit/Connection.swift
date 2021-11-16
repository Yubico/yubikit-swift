//
//  Connection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

public struct Connection {
    public static func connection() async throws -> Connection {
        Thread.sleep(forTimeInterval: 0.5)
        return Connection()
    }
    
    public func session() async throws -> Session {
        Thread.sleep(forTimeInterval: 0.5)
        return Session()
    }
}
