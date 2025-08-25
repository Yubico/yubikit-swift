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
            return try await SessionManager.shared.session()
        }
    }
}

// MARK: - Private

private actor SessionManager {
    static let shared = SessionManager()

    private var connection: SmartCardConnection?
    private var session: PIVSession?

    func session() async throws -> PIVSession {
        guard let session = session else {
            // Create new PIV session with better error handling
            let conn = try await connection()
            let new = try await PIVSession.session(withConnection: conn)
            self.session = new
            return new
        }

        // Return existing
        return session
    }

    private func connection() async throws -> SmartCardConnection {
        guard let connection else {
            // Create new connection with enhanced error handling
            let new = try await WiredSmartCardConnection.connection()
            self.connection = new
            return new
        }

        // Return existing
        return connection
    }
}
