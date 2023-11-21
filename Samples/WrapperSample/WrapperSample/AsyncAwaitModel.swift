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

class AsyncAwaitModel: ObservableObject {
    
    @Published private(set) var status = "No connection"
    
    @MainActor func connect() {
        Task {
            let connection: Connection
            do {
                status = "Trying to connect to YubiKey..."
                connection = try await ConnectionHelper.anyConnection()
                let session = try await OATHSession.session(withConnection: connection)
                let codes = try await session.calculateCodes()
                #if os(iOS)
                await connection.nfcConnection?.close(message: "Calculated codes")
                #endif
                status = "Got \(codes.count) codes from YubiKey using async/await"
            } catch {
                status = "Error: \(error)"
            }
        }
    }
}
