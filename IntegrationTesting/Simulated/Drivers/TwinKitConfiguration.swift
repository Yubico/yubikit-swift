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
import YubiKitTwinSupport

enum TwinKitConfiguration {
    enum Transport: String { case usb, nfc }

    static var hasNFCReader: Bool {
        ProcessInfo.processInfo.environment["YUBIKIT_TWIN_NFC_READER"] != "0"
    }

    static func exposesUSBInterface(_ mask: UInt8) -> Bool {
        let transport = ProcessInfo.processInfo.environment["YUBIKIT_TWIN_TRANSPORT"] ?? "usb"
        guard transport == "usb", let descriptor = try? TwinKitBackend.shared.descriptor() else { return false }
        return descriptor.usbInterfaces & mask != 0
    }

    static func isPresent(_ transport: Transport) throws(SmartCardConnectionError) -> Bool {
        let value = ProcessInfo.processInfo.environment["YUBIKIT_TWIN_TRANSPORT"] ?? "usb"
        guard let selected = Transport(rawValue: value) else {
            throw .setupFailed("Invalid Simulator transport: \(value)")
        }
        if let error = TwinKitBackend.environmentProfileConfigurationError {
            throw .setupFailed(error)
        }
        guard selected == transport else { return false }
        do {
            let descriptor = try TwinKitBackend.shared.descriptor()
            switch transport {
            case .usb: return descriptor.usbInterfaces & 0x04 != 0
            case .nfc: return descriptor.nfcCapabilities != 0
            }
        } catch {
            throw .setupFailed("Cannot read Simulator device descriptor", error)
        }
    }
}
