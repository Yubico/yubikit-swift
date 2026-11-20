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
import YubiKit

/// Evaluates requirements into run-or-skip decisions.
enum Gate {

    enum Decision: Sendable, Equatable {
        case run
        case skip(reason: String)
    }

    static func evaluate(
        _ requirements: Requirements,
        deviceInfo: DeviceInfo?,
        transport: DeviceTransport,
        provider: ProviderCapabilities
    ) -> Decision {
        if case .skip(let reason) = evaluateHost(requirements, transport: transport, provider: provider) {
            return .skip(reason: reason)
        }
        if let deviceInfo {
            if transport == .nfc, deviceInfo.supportedCapabilities[.nfc, default: 0] == 0 {
                return .skip(reason: "the selected YubiKey has no NFC interface")
            }
            if transport == .nfc, deviceInfo.config.enabledCapabilities[.nfc] == 0 {
                return .skip(reason: "NFC applications are disabled on the selected YubiKey")
            }
            if transport == .nfc, deviceInfo.config.isNFCRestricted == true {
                return .skip(reason: "NFC is restricted on the selected YubiKey until USB reinsertion")
            }
            if requirements.requiresLightning, !provider.hasLightning {
                return .skip(reason: "the selected smart-card connection does not use Lightning")
            }
            if let min = requirements.minVersion, deviceInfo.version < min {
                return .skip(reason: "requires firmware ≥ \(min) (device is \(deviceInfo.version))")
            }
            if let max = requirements.maxVersion, deviceInfo.version > max {
                return .skip(reason: "requires firmware ≤ \(max) (device is \(deviceInfo.version))")
            }
            for capability in requirements.capabilities
            where !deviceInfo.isApplicationSupported(capability, over: transport) {
                return .skip(reason: "requires \(capability) over \(transport)")
            }
            // Supported is not enough: a disabled application answers SELECT with "file not found".
            if deviceInfo.config.enabledCapabilities[transport] != nil {
                for capability in requirements.capabilities
                where !deviceInfo.config.isApplicationEnabled(capability, over: transport) {
                    return .skip(reason: "requires \(capability) enabled over \(transport) (disabled on this key)")
                }
            }
            if transport == .usb {
                if requirements.requiresFIDOTransport,
                    let reason = interfaceSkipReason([.u2f, .fido2], named: "FIDO HID", info: deviceInfo)
                {
                    return .skip(reason: reason)
                }
                if requirements.requiresOTPTransport,
                    let reason = interfaceSkipReason([.otp], named: "OTP keyboard HID", info: deviceInfo)
                {
                    return .skip(reason: reason)
                }
                if requirements.needsSmartCardTransport, !provider.hasLightning,
                    let reason = interfaceSkipReason(
                        [.oath, .piv, .openPGP, .hsmAuth],
                        named: "smart-card (CCID)",
                        info: deviceInfo
                    )
                {
                    return .skip(reason: reason)
                }
            }
            // Lightning keys also report `.usb` but carry CTAP2 over their smart-card channel.
            if requirements.requiresCTAP2OverCCID, transport == .usb, !provider.hasLightning {
                if deviceInfo.version < ctap2OverUSBCCIDVersion {
                    return .skip(
                        reason: "CTAP2 over USB CCID requires firmware ≥ 5.8.0 (device is \(deviceInfo.version))"
                    )
                }
            }
            if requirements.requiresBio, !isBio(deviceInfo) {
                return .skip(reason: "requires a Bio (fingerprint) device")
            }
            if requirements.excludesBio, isBio(deviceInfo) {
                return .skip(reason: "requires a non-Bio device")
            }
            if requirements.requiresFIPS, !deviceInfo.isFIPS {
                return .skip(reason: "requires a FIPS-certified device")
            }
            if requirements.excludesFIPS, deviceInfo.isFIPS {
                return .skip(reason: "requires a non-FIPS device")
            }
        }
        return .run
    }

    static func evaluateHost(
        _ requirements: Requirements,
        transport: DeviceTransport,
        provider: ProviderCapabilities
    ) -> Decision {
        if let transports = requirements.transports, !transports.contains(transport) {
            let wanted = transports.map { "\($0)" }.sorted().joined(separator: " or ")
            return .skip(reason: "requires transport \(wanted) (device is on \(transport))")
        }
        if transport == .nfc, !provider.hasSmartCard {
            return .skip(reason: "NFC reading is unavailable on this backend")
        }
        if requirements.requiresFIDOTransport, !provider.hasFIDO {
            return .skip(reason: "requires a FIDO (HID) transport, unavailable on this backend")
        }
        if requirements.needsSmartCardTransport,
            !provider.hasSmartCard && !provider.hasLightning
        {
            return .skip(reason: "requires a smart-card (CCID) transport, unavailable on this backend")
        }
        if requirements.requiresOTPTransport, !provider.hasOTP {
            return .skip(reason: "requires an OTP (keyboard HID) transport, unavailable on this backend")
        }
        if requirements.requiresSCP, !provider.supportsSecureChannel {
            return .skip(reason: "requires Secure Channel (SCP), unsupported by this backend")
        }
        if requirements.requiresRealHardware, provider.isVirtual {
            return .skip(reason: "requires real hardware")
        }
        return .run
    }

    private static func isBio(_ info: DeviceInfo) -> Bool {
        info.formFactor == .usbABio || info.formFactor == .usbCBio || info.fpsVersion != nil
    }

    private static let ctap2OverUSBCCIDVersion = Version("5.8.0")!

    private static func interfaceSkipReason(
        _ applications: [Capability],
        named name: String,
        info: DeviceInfo
    ) -> String? {
        let mask = applications.reduce(UInt(0)) { $0 | $1.rawValue }
        guard (info.supportedCapabilities[.usb] ?? 0) & mask != 0 else {
            return "requires the \(name) interface on the selected YubiKey"
        }
        if let enabled = info.config.enabledCapabilities[.usb], enabled & mask == 0 {
            return "the \(name) interface is disabled on the selected YubiKey"
        }
        return nil
    }
}

extension Scenario {

    /// Returns a skip reason for pre-run UI, or nil if the scenario can run.
    public func skipReason(
        transport: DeviceTransport,
        provider: ProviderCapabilities,
        deviceInfo: DeviceInfo? = nil
    ) -> String? {
        guard
            case .skip(let reason) = Gate.evaluate(
                requirements,
                deviceInfo: deviceInfo,
                transport: transport,
                provider: provider
            )
        else {
            return nil
        }
        return reason
    }
}
