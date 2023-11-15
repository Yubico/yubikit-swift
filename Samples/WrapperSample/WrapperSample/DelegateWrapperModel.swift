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
                self.status = "Error: \(error!)"
                return
            }
            session.calculateCodes { codes, error in
                if let error {
                    self.status = "Error: \(error)"
                    connection.close(error: error) {
                        print("Connection closed with error: \(error)")
                    }
                    return
                }
                guard let codes else { fatalError() }
                self.status = "Got \(codes.count) codes from YubiKey using delegate & callback wrapper"
                #if os(iOS)
                connection.closeIfNFC(message: "Calculated codes") { print("Calculated \(codes.count) codes") }
                #endif
            }
        }
    }
}
