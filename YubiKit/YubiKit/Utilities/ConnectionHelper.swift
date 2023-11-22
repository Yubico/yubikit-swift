// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
#if canImport(CoreNFC)
import CoreNFC
#endif

/// ConnectionHelper simplifies the creation of different connections to the YubiKey by automate
/// much of the work involved in handling multiple different connection at the same time.
public enum ConnectionHelper {
    
    public static func anyConnection(nfcAlertMessage: String? = nil) async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            if NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    try await Task.sleep(for: .seconds(1)) // wait for wired connected yubikeys to connect before starting NFC
                    try Task.checkCancellation()
                    return try await NFCConnection.connection(alertMessage: nfcAlertMessage)
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
