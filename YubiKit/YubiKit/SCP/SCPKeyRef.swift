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

public struct SCPKeyRef: Equatable, Hashable, Sendable {

    public typealias Kid = UInt8

    public init(kid: Kid, kvn: UInt8) {
        self.kid = kid
        self.kvn = kvn
    }

    public let kid: Kid
    public let kvn: UInt8
    public var data: Data { Data([kid, kvn]) }
}

extension SCPKeyRef.Kid {
    public static let scp03: SCPKeyRef.Kid = 0x01
    public static let scp11a: SCPKeyRef.Kid = 0x11
    public static let scp11b: SCPKeyRef.Kid = 0x13
    public static let scp11c: SCPKeyRef.Kid = 0x15
}
