//
//  Version.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-10-26.
//

import Foundation

struct Version: CustomDebugStringConvertible {
    
    init?(withData data: Data) {
        guard data.count == 3 else { return nil }
        let bytes = data.bytes
        major = bytes[0]
        minor = bytes[1]
        micro = bytes[2]
    }
    
    var debugDescription: String {
        "Version: \(major).\(minor).\(micro)"
    }
    
    private let major: UInt8
    private let minor: UInt8
    private let micro: UInt8
}
