//
//  Connection+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-02.
//

import Foundation
import CoreNFC

public enum ConnectionHelper {
    
    public static func anyConnection() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            if NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    try await Task.sleep(for: .seconds(1)) // wait for wired connected yubikeys to connect before starting NFC
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
