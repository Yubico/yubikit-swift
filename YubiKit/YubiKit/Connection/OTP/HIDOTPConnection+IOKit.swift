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

#if os(macOS)

import Foundation
import IOKit
import IOKit.hid
import Logging

private let yubicoVendorID = 0x1050
private let keyboardUsagePage = 0x01
private let keyboardUsage = 0x06

private struct HIDDeviceReference: @unchecked Sendable {
    let device: IOHIDDevice
}

actor HIDOTPConnectionManager: HasOTPLogger {

    static let shared = HIDOTPConnectionManager()

    private let manager: IOHIDManager
    private let eventQueue = DispatchQueue(label: "com.yubico.YubiKit.OTP.HID")
    private var openConnections: [Int: Connection] = [:]

    private final class Connection {
        let device: IOHIDDevice
        let didClose: Promise<Error?>
        init(device: IOHIDDevice, didClose: Promise<Error?>) {
            self.device = device
            self.didClose = didClose
        }
    }

    private init() {
        let hidManager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        manager = hidManager
        IOHIDManagerSetDeviceMatching(
            hidManager,
            [
                kIOHIDVendorIDKey as String: yubicoVendorID,
                kIOHIDDeviceUsagePageKey as String: keyboardUsagePage,
                kIOHIDDeviceUsageKey as String: keyboardUsage,
            ] as CFDictionary
        )
        IOHIDManagerSetDispatchQueue(hidManager, eventQueue)
        IOHIDManagerRegisterDeviceRemovalCallback(
            hidManager,
            { context, _, _, device in
                guard let context,
                    let locationID = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int
                else { return }
                let manager = Unmanaged<HIDOTPConnectionManager>.fromOpaque(context).takeUnretainedValue()
                let removed = HIDDeviceReference(device: device)
                Task { await manager.deviceRemoved(locationID: locationID, removed: removed) }
            },
            Unmanaged.passUnretained(self).toOpaque()
        )
        let result = IOHIDManagerOpen(hidManager, IOOptionBits(kIOHIDOptionsTypeNone))
        if result == kIOReturnSuccess {
            IOHIDManagerActivate(hidManager)
            logger.debug("OTP HID manager opened")
        } else {
            logger.warning("Failed to open OTP HID manager", metadata: ["status": .stringConvertible(result)])
        }
    }

    func availableDevices() -> [HID.YubiKeyDevice] {
        let devices = matchingDevices().compactMap { device -> HID.YubiKeyDevice? in
            guard let locationID = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int,
                let name = IOHIDDeviceGetProperty(device, kIOHIDProductKey as CFString) as? String
            else { return nil }
            let pid = IOHIDDeviceGetProperty(device, kIOHIDProductIDKey as CFString) as? Int
            return HID.YubiKeyDevice(
                hidLocationID: locationID,
                name: name,
                usbProductID: pid.flatMap(UInt16.init(exactly:)),
                usbVendorID: UInt16(yubicoVendorID)
            )
        }
        logger.debug("Enumerated OTP HID devices", metadata: ["count": .stringConvertible(devices.count)])
        return devices
    }

    func open(device: HID.YubiKeyDevice, didClose: Promise<Error?>) throws(OTPConnectionError) {
        logger.debug("Opening OTP HID connection")
        guard openConnections[device.locationID] == nil else {
            logger.debug("OTP HID device is already connected")
            throw .busy
        }
        guard
            let ioDevice = matchingDevices().first(where: {
                (IOHIDDeviceGetProperty($0, kIOHIDLocationIDKey as CFString) as? Int) == device.locationID
            })
        else {
            logger.debug("OTP HID device is no longer available")
            throw .setupFailed("The YubiKey's OTP interface is no longer present")
        }

        // Deliberately unseized: seizing a keyboard needs root and would capture real keystrokes.
        let result = IOHIDDeviceOpen(ioDevice, IOOptionBits(kIOHIDOptionsTypeNone))
        guard result == kIOReturnSuccess else {
            logger.debug("Failed to open OTP HID device", metadata: ["status": .stringConvertible(result)])
            throw .setupFailed("Failed to open the OTP HID interface (\(Self.describe(result)))")
        }
        openConnections[device.locationID] = Connection(device: ioDevice, didClose: didClose)
        logger.debug("OTP HID connection established")
    }

    func close(locationID: Int, didClose: Promise<Error?>, error: Error?) async {
        guard let connection = openConnections[locationID], connection.didClose === didClose else { return }
        openConnections.removeValue(forKey: locationID)
        if let error {
            logger.debug(
                "Closing OTP HID connection with an error",
                metadata: ["errorType": .string(String(reflecting: type(of: error)))]
            )
        } else {
            logger.debug("Closing OTP HID connection")
        }
        IOHIDDeviceClose(connection.device, IOOptionBits(kIOHIDOptionsTypeNone))
        await connection.didClose.fulfill(error)
    }

    func getFeatureReport(from locationID: Int, didClose: Promise<Error?>) async throws(OTPConnectionError) -> Data {
        let device = try connection(for: locationID, didClose: didClose).device
        var buffer = [UInt8](repeating: 0, count: otpFeatureReportSize)
        var length = CFIndex(otpFeatureReportSize)

        let result = IOHIDDeviceGetReport(device, kIOHIDReportTypeFeature, 0, &buffer, &length)
        guard result == kIOReturnSuccess else {
            logger.debug("OTP HID report reception failed", metadata: ["status": .stringConvertible(result)])
            if result == kIOReturnNoDevice {
                await close(locationID: locationID, didClose: didClose, error: OTPConnectionError.connectionLost)
                throw .connectionLost
            }
            throw .receiveFailed("Failed to read an OTP feature report (\(Self.describe(result)))")
        }
        return Data(buffer.prefix(Int(length)))
    }

    func setFeatureReport(
        _ report: Data,
        to locationID: Int,
        didClose: Promise<Error?>
    ) async throws(OTPConnectionError) {
        guard report.count == otpFeatureReportSize else {
            logger.debug("Invalid OTP HID report size", metadata: ["bytes": .stringConvertible(report.count)])
            throw .transmitFailed("An OTP feature report must be exactly \(otpFeatureReportSize) bytes")
        }
        let device = try connection(for: locationID, didClose: didClose).device
        let bytes = Array(report)

        let result = IOHIDDeviceSetReport(device, kIOHIDReportTypeFeature, 0, bytes, bytes.count)
        guard result == kIOReturnSuccess else {
            logger.debug("OTP HID report transmission failed", metadata: ["status": .stringConvertible(result)])
            if result == kIOReturnNoDevice {
                await close(locationID: locationID, didClose: didClose, error: OTPConnectionError.connectionLost)
                throw .connectionLost
            }
            throw .transmitFailed("Failed to write an OTP feature report (\(Self.describe(result)))")
        }
    }

    // MARK: - Private

    private func deviceRemoved(locationID: Int, removed: HIDDeviceReference) async {
        guard let connection = openConnections[locationID],
            Unmanaged.passUnretained(connection.device).toOpaque()
                == Unmanaged.passUnretained(removed.device).toOpaque()
        else { return }
        logger.debug("OTP HID device disconnected")
        await close(locationID: locationID, didClose: connection.didClose, error: OTPConnectionError.connectionLost)
    }

    private func connection(for locationID: Int, didClose: Promise<Error?>) throws(OTPConnectionError) -> Connection {
        guard let connection = openConnections[locationID], connection.didClose === didClose else {
            logger.debug("Cannot use a closed OTP HID connection")
            throw .connectionLost
        }
        return connection
    }

    private func matchingDevices() -> [IOHIDDevice] {
        guard let devices = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else { return [] }
        return Array(devices)
    }

    private static func describe(_ result: IOReturn) -> String {
        switch result {
        case kIOReturnNotPermitted, kIOReturnNotPrivileged:
            return """
                not permitted by IOHIDFamily — Secure Event Input is most likely active \
                (Terminal's Secure Keyboard Entry, a password field, or the lock screen); \
                otherwise check Input Monitoring for the host application
                """
        case kIOReturnExclusiveAccess:
            return "the device is already open exclusively"
        case kIOReturnNoDevice:
            return "the device went away"
        default:
            return "IOReturn 0x\(String(format: "%08X", result))"
        }
    }
}

#endif  // os(macOS)
