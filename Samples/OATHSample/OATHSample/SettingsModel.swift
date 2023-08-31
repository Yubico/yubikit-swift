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

    @MainActor func getKeyVersion() {
        print("await keyVersion()")
        Task {
            self.errorMessage = nil
            do {
                let connection = try await ConnectionHelper.anyConnection()
                print("Got connection in getKeyVersion()")
                let session = try await ManagementSession.session(withConnection: connection)
                self.keyVersion = session.version.debugDescription
                session.end()
                #if os(iOS)
                if let nfcConnection = connection as? NFCConnection {
                    self.connection = "NFC"
                    nfcConnection.close(result: .success("YubiKey version read"))
                } else {
                    self.connection = "Lightning"
                }
                #else
                self.connection = "Smart card"
                #endif
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
