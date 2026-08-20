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
        if let transports = requirements.transports, !transports.contains(transport) {
            let wanted = transports.map { "\($0)" }.sorted().joined(separator: " or ")
            return .skip(reason: "requires transport \(wanted) (device is on \(transport))")
        }
        if let deviceInfo {
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
        if requirements.requiresFIDOTransport, !provider.hasFIDO {
            return .skip(reason: "requires a FIDO (HID) transport, unavailable on this backend")
        }
        if requirements.requiresOTPTransport, !provider.hasOTP {
            return .skip(reason: "requires an OTP (keyboard HID) transport, unavailable on this backend")
        }
        if requirements.requiresLightning, !provider.hasLightning {
            return .skip(reason: "requires a connected Lightning (5Ci) YubiKey")
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
