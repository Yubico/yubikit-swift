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
import SwiftUI
import YubiKit

@MainActor
final class ConnectionManager: ObservableObject {

    static let shared = ConnectionManager()

    @Published private(set) var wiredConnection: SmartCardConnection?
    #if os(iOS)
    @Published private(set) var nfcConnection: NFCSmartCardConnection?
    #endif

    @Published var error: Error?

    private var wiredConnectionTask: Task<Void, Never>?

    private init() {
        startWiredConnection()
    }

    private func startWiredConnection() {
        wiredConnectionTask = Task { @MainActor in
            while !Task.isCancelled {
                do {
                    error = nil
                    guard !Task.isCancelled else { return }

                    let newConnection = try await WiredSmartCardConnection.connection()
                    guard !Task.isCancelled else { return }

                    wiredConnection = newConnection

                    let closeError = await newConnection.connectionDidClose()

                    wiredConnection = nil

                    if let closeError = closeError {
                        error = closeError
                    }
                } catch {
                    // Ignore cancellation errors
                    if let _ = error as? CancellationError { return }
                    self.error = error
                }
            }
        }
    }

    #if os(iOS)
    func requestNFCConnection() async {
        error = nil

        do {
            nfcConnection = try await NFCSmartCardConnection()
        } catch {
            self.error = error
        }
    }

    func closeNFCConnection(message: String? = nil) async {
        error = nil

        await nfcConnection?.close(message: message)
    }
    #endif
}

extension SmartCardConnection {
    var connectionType: String {
        switch self {
        #if os(iOS)
        case _ as NFCSmartCardConnection:
            return "NFC"
        case _ as LightningSmartCardConnection:
            return "Lightning"
        #endif
        case _ as USBSmartCardConnection:
            return "USB"
        default:
            return "Unknown"
        }
    }
}

extension Optional where Wrapped == SmartCardConnection {
    var connectionType: String {
        guard let connection = self else {
            return "No Connection"
        }

        return connection.connectionType
    }
}
