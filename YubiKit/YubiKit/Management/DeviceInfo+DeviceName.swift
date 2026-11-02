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

extension DeviceInfo {
    /// The product name reported by the YubiKey, or inferred from its metadata.
    ///
    /// Uses supported applications and transports, independently of their enabled state.
    /// Incomplete metadata may yield a less specific name.
    internal var deviceName: String {
        if let reportedName { return reportedName }

        let usb = supportedCapabilities[.usb] ?? 0
        // Older firmware does not always report the Security Key and FIPS flags.
        let isSecurityKey = isSKY || (serialNumber == 0 && version < Version("5.2.8")! && Self.isFIDOOnly(usb))
        let isFIPSDevice = isFIPS || (version >= Version("4.4.0")! && version < Version("4.5.0")!)

        if isSecurityKey && version < Version("5.1.0")! {
            return usb & Capability.fido2.rawValue == 0 ? "FIDO U2F Security Key" : "Security Key by Yubico"
        }
        if !isSecurityKey {
            if version.major < 4 {
                if version.major == 0 { return "YubiKey (\(version))" }
                return version.major == 3 ? "YubiKey NEO" : "YubiKey"
            }
            if version.major == 4 {
                if isFIPSDevice { return "YubiKey FIPS (4 Series)" }
                return usb == Capability.otp.rawValue | Capability.u2f.rawValue ? "YubiKey Edge" : "YubiKey 4"
            }
            let previewRanges = [
                Version("5.0.0")!..<Version("5.1.0")!,
                Version("5.2.0")!..<Version("5.2.3")!,
                Version("5.5.0")!..<Version("5.5.2")!,
            ]
            if previewRanges.contains(where: { $0.contains(version) }) { return "YubiKey Preview" }
        }
        guard version >= Version("5.1.0")! else { return "YubiKey 5" }

        let isNano = formFactor == .usbANano || formFactor == .usbCNano
        let isBio = formFactor == .usbABio || formFactor == .usbCBio
        // Some older devices incorrectly report NFC support.
        let hasNFC =
            hasTransport(.nfc) && !isNano && formFactor != .usbCLightning
            && !(formFactor == .usbCKeychain && version < Version("5.2.4")!)
        let isC = formFactor == .usbCKeychain || formFactor == .usbCNano || formFactor == .usbCBio
        var parts = isSecurityKey ? ["Security Key"] : (isBio ? ["YubiKey"] : ["YubiKey", "5"])
        if isC {
            parts.append("C")
        } else if formFactor == .usbCLightning {
            parts.append("Ci")
        }
        if isNano {
            parts.append("Nano")
        } else if hasNFC {
            parts.append("NFC")
        } else if formFactor == .usbAKeychain {
            parts.append("A")
        } else if isBio {
            parts.append("Bio")
        }
        if isFIPSDevice {
            parts.append("FIPS")
        } else if isBio {
            if Self.isFIDOOnly(usb) {
                parts.append("- FIDO Edition")
            } else if usb & Capability.piv.rawValue != 0 {
                parts.append("- Multi-protocol Edition")
            }
        } else if isSecurityKey && serialNumber != 0 {
            parts.append("- Enterprise Edition")
        } else if pinComplexity && !isSecurityKey {
            parts.append("- Enhanced PIN")
        }
        return parts.joined(separator: " ").replacingOccurrences(of: "5 C", with: "5C")
            .replacingOccurrences(of: "5 A", with: "5A")
    }

    private static func isFIDOOnly(_ capabilities: UInt) -> Bool {
        let nonFIDO =
            Capability.otp.rawValue | Capability.oath.rawValue | Capability.piv.rawValue
            | Capability.openPGP.rawValue | Capability.hsmAuth.rawValue
        let fido = Capability.u2f.rawValue | Capability.fido2.rawValue
        return capabilities & nonFIDO == 0 && capabilities & fido != 0
    }
}
