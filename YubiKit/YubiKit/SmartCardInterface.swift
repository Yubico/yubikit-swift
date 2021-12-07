//
//  SmartCardInterface.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-26.
//

import Foundation

public actor SmartCardInterface {
    
    let queue = DispatchQueue(label: "com.yubico.smartcardinterface")
    
    enum Application {
        case PIV
        case OATH
        case Management
    }
    
    struct APDU {}
    
    func selectApplication(application: Application) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                emulateSlowTask()
                continuation.resume()
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
