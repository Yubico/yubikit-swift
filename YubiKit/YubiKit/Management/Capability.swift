//
//  Capability.swift
//  YubiKit
//
//  Created by Jens Utbult on 2024-05-17.
//

import Foundation

/// Identifies a feature (typically an application) on a YubiKey which may or may not be supported, and which can be enabled or disabled.
public enum Capability: UInt {
    /// Identifies the YubiOTP application.
    case OTP = 0x0001
    /// Identifies the U2F (CTAP1) portion of the FIDO application.
    case U2F = 0x0002
    /// Identifies the OpenPGP application, implementing the OpenPGP Card protocol.
    case OPENPGP = 0x0008
    /// Identifies the PIV application, implementing the PIV protocol.
    case PIV = 0x0010
    /// Identifies the OATH application, implementing the YKOATH protocol.
    case OATH = 0x0020
    /// Identifies the HSMAUTH application.
    case HSMAUTH = 0x0100
    /// Identifies the FIDO2 (CTAP2) portion of the FIDO application.
    case FIDO2 = 0x0200

    var bit: UInt { self.rawValue }
}

extension Capability {
    internal static func translateMaskFrom(fipsMask: UInt) -> UInt {
        var capabilities: UInt = 0
        if fipsMask & 0b00000001 != 0 {
            capabilities |= Capability.FIDO2.bit
        }
        if fipsMask & 0b00000010 != 0 {
            capabilities |= Capability.PIV.bit
        }
        if fipsMask & 0b00000100 != 0 {
            capabilities |= Capability.OPENPGP.bit
        }
        if fipsMask & 0b00001000 != 0 {
            capabilities |= Capability.OATH.bit
        }
        if fipsMask & 0b00010000 != 0 {
            capabilities |= Capability.HSMAUTH.bit
        }
        return capabilities
    }
}
