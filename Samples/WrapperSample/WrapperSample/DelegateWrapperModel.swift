//
//  DelegateWrapperModel.swift
//  WrapperSample
//
//  Created by Jens Utbult on 2022-12-09.
//

import Foundation
import YubiKit

class DelegateWrapperModel: ObservableObject, YubKitWrapperDelegate {

    @Published private(set) var status = "No connection"
    let yubikit = YubiKitWrapper()

    init() {
        yubikit.delegate = self
    }
    
    @MainActor func connect() {
        status = "Trying to connect to YubiKey..."
        yubikit.startAnyConnection()
    }
    
    func didConnect(connection: YubiKit.Connection) {
        OATHSession.session(withConnection: connection) { session, error in
            guard let session = session as? OATHSession else {
                self.status = "⚠️ error: \(error!)"
                return
            }
            session.calculateCodes { codes, error in
                guard let codes else {
                    DispatchQueue.main.async {
                        self.status = "⚠️ error: \(error!)"
                    }
                    if let nfcConnection = connection as? NFCConnection {
                        nfcConnection.close(result: .failure("Error: \(error!.localizedDescription)"))
                    }
                    return
                }
                DispatchQueue.main.async {
                    self.status = "Got \(codes.count) codes from YubiKey using delegate & callback wrapper"
                }
                session.end()
                if let nfcConnection = connection as? NFCConnection {
                    nfcConnection.close(result: .success("Calculated codes"))
                }
            }
        }
    }
}
