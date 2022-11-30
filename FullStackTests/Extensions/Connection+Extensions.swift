//
//  Connection+Extensions.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2022-11-24.
//

import Foundation
import YubiKit
import CoreNFC

enum ConnectionHandler {
    
    static func anyConnection() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            if  NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    try await Task.sleep(nanoseconds: 1_000_000_000) // wait for lightning to connect for 1 second
                    try Task.checkCancellation()
                    return try await NFCConnection.connection()
                }
            }
//            group.addTask {
//                return try await LightningConnection.connection()
//            }
            group.addTask {
                return try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            print("Group returned \(result)")
            return result
        }
        print("taskgroup returned")
        return connection
    }
}
