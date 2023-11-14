//
//  Connection+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-02.
//

import Foundation
#if canImport(CoreNFC)
import CoreNFC
#endif

public enum ConnectionHelper {
    
    public static func anyConnection() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            if NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    try await Task.sleep(for: .seconds(1)) // wait for wired connected yubikeys to connect before starting NFC
                    try Task.checkCancellation()
                    return try await NFCConnection.connection()
                }
            }
            group.addTask {
                return try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                return try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }
    
    
    public static func anyWiredConnection() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            group.addTask {
                return try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                return try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }
    
    public static func wiredConnections() -> ConnectionHelper.AnyWiredConnections {
        return AnyWiredConnections()
    }
    
    public static func anyConnections() -> ConnectionHelper.AnyConnections {
        return AnyConnections()
    }
    #if os(iOS)
    public static func startNFC() async throws {
       let _ = try await NFCConnection.connection()
    }
    #endif
    
    public struct AnyWiredConnections: AsyncSequence {
        public typealias Element = Connection
        var current: Connection? = nil
        public struct AsyncIterator: AsyncIteratorProtocol {
            mutating public func next() async -> Element? {
                while true {
                    return try? await ConnectionHelper.anyWiredConnection()
                }
            }
        }
        
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator()
        }
    }
    
    public struct AnyConnections: AsyncSequence {
        public typealias Element = Connection
        var current: Connection? = nil
        public struct AsyncIterator: AsyncIteratorProtocol {
            mutating public func next() async -> Element? {
                while true {
                    return try? await ConnectionHelper.anyConnection()
                }
            }
        }
        
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator()
        }
    }
    
}
