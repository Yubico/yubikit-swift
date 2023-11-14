//
//  SettingsModel.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-25.
//

import Foundation
import YubiKit

class SettingsModel: ObservableObject {
    
    @Published private(set) var error: Error?
    @Published private(set) var keyVersion: String?
    @Published private(set) var connection: String?

    @MainActor func getKeyVersion() {
        Task {
            self.error = nil
            do {
                let connection = try await ConnectionHelper.anyConnection()
                let session = try await ManagementSession.session(withConnection: connection)
                self.keyVersion = session.version.debugDescription
                #if os(iOS)
                if let nfcConnection = connection.nfcConnection {
                    self.connection = "NFC"
                    await nfcConnection.close(message: "YubiKey version read")
                } else {
                    self.connection = connection as? SmartCardConnection != nil ? "SmartCard" : "Lightning"
                }
                #else
                self.connection = "SmartCard"
                #endif
            } catch {
                self.error = error
            }
        }
    }
}
