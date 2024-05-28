// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

/// The firmware version of the YubiKey.
public struct Version: Comparable, CustomStringConvertible {
    
    public let major: UInt8
    public let minor: UInt8
    public let micro: UInt8
    
    internal init?(withData data: Data) {
        guard data.count == 3 else { return nil }
        let bytes = data.bytes
        major = bytes[0]
        minor = bytes[1]
        micro = bytes[2]
    }
    
    /// Create a new Version from a version string, e.g. "5.7.0".
    public init?(withString string: String) {
        let components = string.components(separatedBy: ".")
        guard components.count == 3,
              let major = UInt8(components[0]),
              let minor = UInt8(components[1]),
              let micro = UInt8(components[2])
        else { return nil }
        self.major = major
        self.minor = minor
        self.micro = micro
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
    
    /// String representaion of the firmware version e.g "5.2.3".
    public var description: String {
        "\(major).\(minor).\(micro)"
    }
}
