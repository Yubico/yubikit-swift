//
//  CallbackWrapper.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-09.
//

import Foundation

extension Connection {
    public static func connection(callback: @escaping (Connection?, Error?) -> Void) {
        Task {
            do {
                let connection = try await self.connection()
                callback(connection, nil)
            } catch {
                callback(nil, error)
            }
        }
    }
    
    public func close(error: Error?, callback: @escaping () -> Void) {
        Task { @MainActor in
            await self.close(error: error)
            callback()
        }
    }
}

#if os(iOS)
extension Connection {
    public func closeIfNFC(message: String?, callback: @escaping () -> Void) {
        Task { @MainActor in
            await self.nfcConnection?.close(message: message)
            callback()
        }
    }
}

#endif

extension ConnectionHelper {
    public static func anyConnection(callback: @escaping (Connection?, Error?) -> Void) {
        Task {
            do {
                let connection = try await self.anyConnection()
                callback(connection, nil)
            } catch {
                callback(nil, error)
            }
        }
    }
}

extension Session {
    public static func session(withConnection connection: Connection, callback: @escaping (Session?, Error?) -> Void) {
        Task {
            do {
                let session = try await self.session(withConnection: connection)
                callback(session, nil)
            } catch {
                callback(nil, error)
            }
        }
    }
}

extension OATHSession {
    public func calculateCode(for credential: Credential, timestamp: Date = Date(), callback: @escaping (OATHSession.Code?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let code = try await self.calculateCode(credential: credential, timestamp: timestamp)
                callback(code, nil)
            } catch {
                callback(nil, error)
            }
        }
    }
    
    public func calculateCodes(timestamp: Date = Date(), callback: @escaping ([(OATHSession.Credential, OATHSession.Code?)]?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let result = try await self.calculateCodes(timestamp: timestamp)
                callback(result, nil)
            } catch {
                callback(nil, error)
            }
        }
    }
}
