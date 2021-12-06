//
//  SmartCardInterface.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-26.
//

import Foundation

public actor SmartCardInterface {
    
    enum Application {
        case PIV
        case OATH
        case Management
    }
    
    struct APDU {}
    
    func selectApplication(application: Application) async throws {
        emulateSlowTask()
        return
    }
    
    func sendCommand(apdu: APDU) async throws -> Data {
        emulateSlowTask()
        return Data()
    }
    
}
