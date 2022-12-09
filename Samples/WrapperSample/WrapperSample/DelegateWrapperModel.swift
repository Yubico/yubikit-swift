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
                    self.status = "⚠️ error: \(error!)"
                    return
                }
                DispatchQueue.main.async {
                    self.status = "Got \(codes.count) codes from YubiKey using delegate & callback wrapper"
                }
            }
        }
    }
}
