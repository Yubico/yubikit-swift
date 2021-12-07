//
//  SettingsModel.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-25.
//

import Foundation
import YubiKit

class SettingsModel: ObservableObject {
    @Published private(set) var errorMessage: String?
    @Published private(set) var keyVersion: String?
    @Published private(set) var connection: String?

    private var connectionHandler = ConnectionHandler()
    
    @MainActor func getKeyVersion() {
        print("await keyVersion()")
        Task {
            self.errorMessage = nil
            do {
                let connection = try await connectionHandler.connection(type: .any)
                print("Got connection in getKeyVersion()")
                let session = try await ManagementSession.session(withConnection: connection)
                self.keyVersion = try await session.getKeyVersion()
                if connection.type == .nfc {
                    self.connection = "NFC"
                    await session.end(result: nil, closingConnection: true)
                } else {
                    self.connection = "Lightning"
                }
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
