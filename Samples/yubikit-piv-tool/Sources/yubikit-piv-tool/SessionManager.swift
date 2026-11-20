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

extension PIVSession {
    static func shared() async throws -> PIVSession {
        try await SessionManager.shared.makeSession()
    }

    static func closeSharedConnection(error: Swift.Error? = nil) async {
        await SessionManager.shared.close(error: error)
    }
}

private actor SessionManager {
    static let shared = SessionManager()

    private var connection: SmartCardConnection?
    private var session: PIVSession?

    func makeSession() async throws -> PIVSession {
        if let session { return session }

        let connection: SmartCardConnection
        do {
            connection = try await WiredSmartCardConnection.makeConnection()
        } catch {
            throw connectionError(error)
        }
        self.connection = connection
        do {
            // Management discovery lets the SDK resolve development firmware versions.
            _ = try? await Management.Session.makeSession(connection: connection)
            let session = try await PIVSession.makeSession(connection: connection)
            self.session = session
            return session
        } catch {
            await close(error: error)
            throw pivError(error)
        }
    }

    func close(error: Error?) async {
        let connection = self.connection
        self.connection = nil
        session = nil
        await connection?.close(error: error)
    }
}
