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

/// A reference to a Secure Channel Protocol key, identified by key ID and key version number.
public struct SCPKeyRef: Equatable, Hashable, Sendable {

    /// The key identifier type.
    public typealias Kid = UInt8

    /// Creates a key reference with the specified key ID and version.
    /// - Parameters:
    ///   - kid: The key identifier.
    ///   - kvn: The key version number.
    public init(kid: Kid, kvn: UInt8) {
        self.kid = kid
        self.kvn = kvn
    }

    /// The key identifier.
    public let kid: Kid

    /// The key version number.
    public let kvn: UInt8

    /// The key reference as raw data bytes.
    public var data: Data { Data([kid, kvn]) }
}

extension SCPKeyRef.Kid {

    /// Key ID for SCP03.
    public static let scp03: SCPKeyRef.Kid = 0x01

    /// Key ID for SCP11a.
    public static let scp11a: SCPKeyRef.Kid = 0x11

    /// Key ID for SCP11b.
    public static let scp11b: SCPKeyRef.Kid = 0x13

    /// Key ID for SCP11c.
    public static let scp11c: SCPKeyRef.Kid = 0x15
}
