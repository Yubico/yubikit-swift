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
