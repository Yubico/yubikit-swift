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
import YubiKit

// Convenience method to get a shared PIV session
extension PIVSession {
    static func shared() async throws -> PIVSession {
        do {
            return try await SessionManager.shared.makeSession()
        }
    }
}

// MARK: - Private

private actor SessionManager {
    static let shared = SessionManager()

    private var connection: SmartCardConnection?
    private var session: PIVSession?

    func makeSession() async throws -> PIVSession {
        guard let session = session else {
            // Create new PIV session with better error handling
            let conn = try await makeConnection()
            do {
                let new = try await PIVSession.makeSession(connection: conn)
                self.session = new
                return new
            } catch {
                handlePIVError(error)
            }
        }

        // Return existing
        return session
    }

    private func makeConnection() async throws -> SmartCardConnection {
        guard let connection else {
            // Create new connection with enhanced error handling
            do {
                let new = try await WiredSmartCardConnection.makeConnection()
                self.connection = new
                return new
            } catch {
                handleConnectionError(error)
            }
        }

        // Return existing
        return connection
    }
}
