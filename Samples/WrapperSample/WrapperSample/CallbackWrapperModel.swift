//
//  CallbackWrapperModel.swift
//  WrapperSample
//
//  Created by Jens Utbult on 2022-12-09.
//

import Foundation
import YubiKit

class CallbackWrapperModel: ObservableObject {
    
    @Published private(set) var status = "No connection"
    
    @MainActor func connect() {
        
        status = "Trying to connect to YubiKey..."
        
        ConnectionHelper.anyConnection() { connection, error in
            guard let connection else {
                self.status = "Error: \(error!)"
                return
            }
            OATHSession.session(withConnection: connection) { session, error in
                guard let session = session as? OATHSession else {
                    connection.close(error: error!) { }
                    self.status = "Error: \(error!)"
                    return
                }
                session.calculateCodes { codes, error in
                    guard let codes else {
                        self.status = "Error: \(error!)"
                        return
                    }
                    self.status = "Got \(codes.count) codes from YubiKey using callback wrapper"
                    #if os(iOS)
                    connection.closeIfNFC(message: "Calculated codes") { print("Closed") }
                    #endif
                }
            }
        }
    }
}
