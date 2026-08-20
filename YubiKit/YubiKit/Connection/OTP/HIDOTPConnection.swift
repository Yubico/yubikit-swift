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

/// A connection to the Yubico OTP application over the YubiKey's keyboard HID interface.
///
/// Unlike ``HIDFIDOConnection``, this connection:
/// - matches the keyboard usage (usage page `0x01`, usage `0x06`) rather than FIDO's `0xF1D0`,
/// - opens the device **unseized** — seizing a keyboard-usage device requires root
///   (`kIOReturnNotPrivileged`) and would steal the user's keystrokes, and
/// - exchanges synchronous *feature* reports, so it needs no input-report callback and no run loop.
///
/// ## macOS requirements
///
/// Reading feature reports from a keyboard-usage device is, behaviourally, what a keylogger does, so
/// macOS gates it on Input Monitoring. A command-line tool inherits the grant of its host terminal.
/// No code-signing entitlement is involved: the `com.apple.hid.manager.user-access-*` entitlements
/// are restricted, so a binary carrying them without a provisioning profile is killed by AMFI at
/// launch, and an ad-hoc signature with no entitlements at all works fine.
///
/// > Important: **Secure Event Input** blocks this connection outright. It is a system-wide flag —
/// asserted by Terminal's *Secure Keyboard Entry* setting, by password fields, and by the lock
/// screen — and while it is held, every unprivileged process reading a keyboard HID device gets
/// `kIOReturnNotPermitted`, regardless of Input Monitoring. It is not specific to this SDK; ykman
/// fails identically. Check with
/// `ioreg -l -d 1 -k IOConsoleUsers | grep kCGSSessionSecureInputPID`, which names the process
/// holding it. Running as root bypasses the check.
///
/// ``SmartCardConnection`` reaches the same YubiOTP application with none of these requirements,
/// and is the *only* option on iOS and over NFC.
public struct HIDOTPConnection: Sendable, OTPConnection {

    /// The HID device this connection is associated with.
    private let device: HID.YubiKeyDevice

    private var locationID: Int { device.locationID }

    /// Returns every YubiKey currently exposing an OTP keyboard interface.
    ///
    /// A YubiKey only exposes it when the Yubico OTP application is enabled over USB, so an empty
    /// result is a normal configuration rather than an error.
    package static func availableDevices() async throws(OTPConnectionError) -> [HID.YubiKeyDevice] {
        await HIDOTPConnectionManager.shared.availableDevices()
    }

    /// Creates a connection to the first YubiKey exposing an OTP keyboard interface.
    ///
    /// - Throws: ``OTPConnectionError/noDevicesFound`` if no such YubiKey is present.
    public init() async throws(OTPConnectionError) {
        guard let first = try await HIDOTPConnection.availableDevices().first else {
            throw OTPConnectionError.noDevicesFound
        }
        try await self.init(device: first)
    }

    private init(device: HID.YubiKeyDevice) async throws(OTPConnectionError) {
        try await HIDOTPConnectionManager.shared.open(device: device)
        self.device = device
    }

    package static func makeConnection(
        device: HID.YubiKeyDevice
    ) async throws(OTPConnectionError) -> HIDOTPConnection {
        try await HIDOTPConnection(device: device)
    }

    public static func makeConnection() async throws(OTPConnectionError) -> HIDOTPConnection {
        try await HIDOTPConnection()
    }

    public func close(error: Error?) async {
        await HIDOTPConnectionManager.shared.close(locationID: locationID, error: error)
    }

    public func waitUntilClosed() async -> Error? {
        await HIDOTPConnectionManager.shared.waitUntilClosed(locationID: locationID)
    }

    public func send(_ report: Data) async throws(OTPConnectionError) {
        try await HIDOTPConnectionManager.shared.setFeatureReport(report, to: locationID)
    }

    public func receive() async throws(OTPConnectionError) -> Data {
        try await HIDOTPConnectionManager.shared.getFeatureReport(from: locationID)
    }
}

// MARK: - Private helpers

private let yubicoVendorID = 0x1050
private let keyboardUsagePage = 0x01
private let keyboardUsage = 0x06

/// Serializes IOKit access to the OTP keyboard interface.
///
/// This is an actor rather than the dedicated-thread-plus-run-loop design of the FIDO manager:
/// feature reports are synchronous IOKit calls with no callbacks, so there is no run loop to pump.
/// The actor exists purely to keep calls to a given device ordered.
private actor HIDOTPConnectionManager: HasOTPLogger {

    static let shared = HIDOTPConnectionManager()

    private let manager: IOHIDManager
    private var openConnections: [Int: Connection] = [:]

    private final class Connection {
        let device: IOHIDDevice
        let didClose = Promise<Error?>()
        init(device: IOHIDDevice) { self.device = device }
    }

    private init() {
        manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        IOHIDManagerSetDeviceMatching(
            manager,
            [
                kIOHIDVendorIDKey as String: yubicoVendorID,
                kIOHIDDeviceUsagePageKey as String: keyboardUsagePage,
                kIOHIDDeviceUsageKey as String: keyboardUsage,
            ] as CFDictionary
        )
        _ = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
    }

    func availableDevices() -> [HID.YubiKeyDevice] {
        matchingDevices().compactMap { device in
            guard let locationID = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int,
                let name = IOHIDDeviceGetProperty(device, kIOHIDProductKey as CFString) as? String
            else { return nil }
            return HID.YubiKeyDevice(hidLocationID: locationID, name: name)
        }
    }

    func open(device: HID.YubiKeyDevice) throws(OTPConnectionError) {
        guard openConnections[device.locationID] == nil else { throw .busy }
        guard
            let ioDevice = matchingDevices().first(where: {
                (IOHIDDeviceGetProperty($0, kIOHIDLocationIDKey as CFString) as? Int) == device.locationID
            })
        else {
            throw .setupFailed("The YubiKey's OTP interface is no longer present")
        }

        // Deliberately unseized: seizing a keyboard needs root and would capture real keystrokes.
        let result = IOHIDDeviceOpen(ioDevice, IOOptionBits(kIOHIDOptionsTypeNone))
        guard result == kIOReturnSuccess else {
            throw .setupFailed("Failed to open the OTP HID interface (\(Self.describe(result)))")
        }
        openConnections[device.locationID] = Connection(device: ioDevice)
    }

    func close(locationID: Int, error: Error?) async {
        guard let connection = openConnections.removeValue(forKey: locationID) else { return }
        IOHIDDeviceClose(connection.device, IOOptionBits(kIOHIDOptionsTypeNone))
        await connection.didClose.fulfill(error)
    }

    func waitUntilClosed(locationID: Int) async -> Error? {
        guard let connection = openConnections[locationID] else { return nil }
        return try? await connection.didClose.value()
    }

    func getFeatureReport(from locationID: Int) throws(OTPConnectionError) -> Data {
        let device = try connection(for: locationID).device
        var buffer = [UInt8](repeating: 0, count: otpFeatureReportSize)
        var length = CFIndex(otpFeatureReportSize)

        let result = IOHIDDeviceGetReport(device, kIOHIDReportTypeFeature, 0, &buffer, &length)
        guard result == kIOReturnSuccess else {
            throw .receiveFailed("Failed to read an OTP feature report (\(Self.describe(result)))")
        }
        return Data(buffer.prefix(Int(length)))
    }

    func setFeatureReport(_ report: Data, to locationID: Int) throws(OTPConnectionError) {
        guard report.count == otpFeatureReportSize else {
            throw .transmitFailed("An OTP feature report must be exactly \(otpFeatureReportSize) bytes")
        }
        let device = try connection(for: locationID).device
        let bytes = Array(report)

        let result = IOHIDDeviceSetReport(device, kIOHIDReportTypeFeature, 0, bytes, bytes.count)
        guard result == kIOReturnSuccess else {
            throw .transmitFailed("Failed to write an OTP feature report (\(Self.describe(result)))")
        }
    }

    // MARK: - Private

    private func connection(for locationID: Int) throws(OTPConnectionError) -> Connection {
        guard let connection = openConnections[locationID] else { throw .connectionLost }
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
