//
//  Session.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

extension String: Error {}

public struct Session {

    public func calculateCode() async throws -> String {
        Thread.sleep(forTimeInterval: 0.5)
        return "\(Int.random(in: 1...6))"
    }
    
    public func calculateFailingCode() async throws -> String {
        Thread.sleep(forTimeInterval: 0.5)
        throw "Something went wrong!"
    }

}
