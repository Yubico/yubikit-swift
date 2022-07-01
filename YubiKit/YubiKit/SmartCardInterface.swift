//
//  SmartCardInterface.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-26.
//

import Foundation
/*
public actor _SmartCardInterface {
    
    let queue = DispatchQueue(label: "com.yubico.smartcardinterface")
    
    enum Application {
        case PIV
        case OATH
        case Management
    }
    
    struct APDU {}
    
    func selectApplication(application: Application) async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            queue.async {
                emulateSlowTask()
                continuation.resume(returning: Data())
            }
        }
    }
    
    func sendCommand(apdu: APDU) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                emulateSlowTask()
                continuation.resume(returning: Data())
            }
        }
    }
}
*/
