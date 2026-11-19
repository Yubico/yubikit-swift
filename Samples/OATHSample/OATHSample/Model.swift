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

struct Account: Identifiable {
    let id: Data
    let label: String
    let code: String?
    let issuer: String?
}

@MainActor
final class Model: ObservableObject {
    @Published private(set) var accounts = [Account]()
    @Published private(set) var keyVersion: String?
    @Published private(set) var connectionType: String?
    @Published private(set) var isScanning = false
    @Published private(set) var hasWiredConnection = false
    @Published private(set) var readError: Error?
    @Published var error: Error?

    func monitorWiredConnections(
        makeConnection: () async throws -> SmartCardConnection = {
            try await WiredSmartCardConnection.makeConnection()
        }
    ) async {
        var reportedDiscoveryError = false
        while !Task.isCancelled {
            do {
                if isScanning {
                    try await Task.sleep(for: .milliseconds(100))
                    continue
                }
                let connection = try await makeConnection()
                guard !Task.isCancelled else {
                    await connection.close(error: nil)
                    return
                }
                // NFC owns the display until its scan has finished.
                if isScanning {
                    await connection.close(error: nil)
                    continue
                }
                hasWiredConnection = true
                reportedDiscoveryError = false
                clear()
                error = nil
                await withTaskCancellationHandler {
                    await update(using: connection)
                    let closeError = await connection.waitUntilClosed()
                    clear()
                    if !Task.isCancelled, let closeError {
                        error = closeError
                    }
                } onCancel: {
                    // Cancellation alone does not end waitUntilClosed().
                    Task { await connection.close(error: nil) }
                }
                hasWiredConnection = false
            } catch {
                guard !Task.isCancelled else { return }
                if !isScanning, !reportedDiscoveryError {
                    self.error = error
                    reportedDiscoveryError = true
                }
                // Persistent discovery errors must not create a busy loop.
                do {
                    try await Task.sleep(for: .seconds(1))
                } catch {
                    return
                }
            }
        }
    }

    #if os(iOS)
    func scanNFC() async {
        guard !isScanning, !hasWiredConnection else { return }
        isScanning = true
        defer { isScanning = false }
        clear()
        error = nil
        do {
            let connection = try await NFCSmartCardConnection()
            guard !Task.isCancelled else {
                await connection.close(error: nil)
                return
            }
            await withTaskCancellationHandler {
                let succeeded = await update(using: connection)
                if succeeded {
                    await connection.close(message: "Codes calculated")
                } else {
                    await connection.close(error: error)
                }
            } onCancel: {
                Task { await connection.close(error: nil) }
            }
        } catch SmartCardConnectionError.cancelledByUser {
            return
        } catch SmartCardConnectionError.cancelled {
            return
        } catch {
            guard !Task.isCancelled else { return }
            self.error = error
        }
    }
    #endif

    @discardableResult
    func update(using connection: SmartCardConnection) async -> Bool {
        do {
            try Task.checkCancellation()
            let session = try await OATHSession.makeSession(connection: connection)
            let result = try await session.calculateCredentialCodes()
            let version = await session.version.description
            try Task.checkCancellation()
            accounts = result.map { credential, code in
                Account(id: credential.id, label: credential.label, code: code?.code, issuer: credential.issuer)
            }
            keyVersion = version
            readError = nil
            connectionType = connection.connectionType
            error = nil
            return true
        } catch {
            guard !Task.isCancelled else { return false }
            clear()
            readError = error
            self.error = error
            return false
        }
    }

    private func clear() {
        readError = nil
        accounts = []
        keyVersion = nil
        connectionType = nil
    }
}
