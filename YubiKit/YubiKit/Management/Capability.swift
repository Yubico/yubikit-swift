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

/// Identifies a feature (typically an application) on a YubiKey which may or may not be supported, and which can be enabled or disabled.
public enum Capability: UInt, Sendable {
    /// Identifies the YubiOTP application.
    case otp = 0x0001
    /// Identifies the U2F (CTAP1) portion of the FIDO application.
    case u2f = 0x0002
    /// Identifies the OpenPGP application, implementing the OpenPGP Card protocol.
    case openPGP = 0x0008
    /// Identifies the PIV application, implementing the PIV protocol.
    case piv = 0x0010
    /// Identifies the OATH application, implementing the YKOATH protocol.
    case oath = 0x0020
    /// Identifies the HSMAUTH application.
    case hsmAuth = 0x0100
    /// Identifies the FIDO2 (CTAP2) portion of the FIDO application.
    case fido2 = 0x0200

    var bit: UInt { self.rawValue }
}

extension Capability {
    internal static func translateMaskFrom(fipsMask: UInt) -> UInt {
        var capabilities: UInt = 0
        if fipsMask & 0b00000001 != 0 {
            capabilities |= Capability.fido2.bit
        }
        if fipsMask & 0b00000010 != 0 {
            capabilities |= Capability.piv.bit
        }
        if fipsMask & 0b00000100 != 0 {
            capabilities |= Capability.openPGP.bit
        }
        if fipsMask & 0b00001000 != 0 {
            capabilities |= Capability.oath.bit
        }
        if fipsMask & 0b00010000 != 0 {
            capabilities |= Capability.hsmAuth.bit
        }
        return capabilities
    }
}
