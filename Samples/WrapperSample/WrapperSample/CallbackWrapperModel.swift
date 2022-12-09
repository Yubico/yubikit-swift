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
       ConnectionHelper.anyConnection() { connection, error in
            guard let connection else {
                self.status = "🧅 error: \(error!)"
                return
            }
            OATHSession.session(withConnection: connection) { session, error in
                guard let session = session as? OATHSession else {
                    self.status = "🧅 error: \(error!)"
                    return
                }
                session.calculateCodes { codes, error in
                    guard let codes else {
                        self.status = "🧅 error: \(error!)"
                        return
                    }
                    DispatchQueue.main.async {
                        self.status = "Got \(codes.count) codes from YubiKey using callback wrapper"
                    }
                    if connection as? NFCConnection != nil {
                        session.end(withConnectionStatus: .close(.success("Read data from YubiKey"))) {
                            print("session closed")
                        }
                    }
                }
            }
        }
    }
}
