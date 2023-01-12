//
//  Version.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-10-26.
//

import Foundation

public struct Version: Comparable, CustomDebugStringConvertible {
    
    public let major: UInt8
    public let minor: UInt8
    public let micro: UInt8
    
    init?(withData data: Data) {
        guard data.count == 3 else { return nil }
        let bytes = data.bytes
        major = bytes[0]
        minor = bytes[1]
        micro = bytes[2]
    }
    
    public static func < (lhs: Version, rhs: Version) -> Bool {
        if lhs.major != rhs.major {
            return lhs.major < rhs.major
        } else if lhs.minor != rhs.minor {
            return lhs.minor < rhs.minor
        } else {
            return lhs.micro < rhs.micro
        }
    }
    
    public static func == (lhs: Version, rhs: Version) -> Bool {
        return lhs.major == rhs.major && lhs.minor == rhs.minor && lhs.micro == rhs.micro
    }

    public var debugDescription: String {
        "Version: \(major).\(minor).\(micro)"
    }
}
