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
                self.status = "🧅 error: \(error!)"
                return
            }
            OATHSession.session(withConnection: connection) { session, error in
                guard let session = session as? OATHSession else {
                    DispatchQueue.main.async {
                        self.status = "🧅 error: \(error!)"
                    }
                    return
                }
                session.calculateCodes { codes, error in
                    guard let codes else {
                        DispatchQueue.main.async {
                            self.status = "🧅 error: \(error!)"
                        }
                        return
                    }
                    DispatchQueue.main.async {
                        self.status = "Got \(codes.count) codes from YubiKey using callback wrapper"
                    }
                    session.end()
                    if let nfcConnection = connection as? NFCConnection {
                        nfcConnection.close(result: .success("Calculated codes"))
                    }
                }
            }
        }
    }
}
