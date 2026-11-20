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
import Logging

/// A connection to the Yubico OTP application over the keyboard HID interface of a YubiKey.
///
/// The Yubico OTP application must be enabled over USB.
public struct HIDOTPConnection: Sendable, OTPConnection {
    /// Creates a connection to the first YubiKey exposing an OTP keyboard interface.
    ///
    /// Waits until a YubiKey exposing an OTP keyboard interface becomes available.
    ///
    /// - Throws: ``OTPConnectionError/cancelled`` if the task is cancelled while waiting,
    ///   or another ``OTPConnectionError`` if discovery or connection setup fails.
    public init() async throws(OTPConnectionError) {
        let first = try await waitForDevice(cancellationError: OTPConnectionError.cancelled) {
            () async throws(OTPConnectionError) in
            try await Self.availableDevices()
        }
        try await self.init(device: first)
    }

    /// Waits for a YubiKey exposing an OTP keyboard interface and connects to it.
    ///
    /// - Throws: ``OTPConnectionError/cancelled`` if the task is cancelled while waiting,
    ///   or another ``OTPConnectionError`` if discovery or connection setup fails.
    public static func makeConnection() async throws(OTPConnectionError) -> HIDOTPConnection {
        try await HIDOTPConnection()
    }

    /// Closes the connection.
    public func close(error: Error?) async {
        await HIDOTPConnectionManager.shared.close(locationID: locationID, didClose: didClose, error: error)
    }

    /// Waits until the connection closes.
    public func waitUntilClosed() async -> Error? {
        try? await didClose.value()
    }

    /// Sends one 8-byte OTP feature report.
    public func send(_ report: Data) async throws(OTPConnectionError) {
        try await HIDOTPConnectionManager.shared.setFeatureReport(report, to: locationID, didClose: didClose)
    }

    /// Receives one 8-byte OTP feature report.
    public func receive() async throws(OTPConnectionError) -> Data {
        try await HIDOTPConnectionManager.shared.getFeatureReport(from: locationID, didClose: didClose)
    }

    /// Returns the available YubiKey OTP interfaces.
    /// - Parameter matching: A case-insensitive substring, or `nil` for every YubiKey.
    public static func availableDevices(
        matching: String? = nil
    ) async throws(OTPConnectionError) -> [HID.YubiKeyDevice] {
        let devices = await HIDOTPConnectionManager.shared.availableDevices()
        guard let matching else { return devices }
        return devices.filter { $0.name.localizedCaseInsensitiveContains(matching) }
    }

    /// Opens the OTP interface of a device returned by ``availableDevices(matching:)``.
    public static func makeConnection(
        device: HID.YubiKeyDevice
    ) async throws(OTPConnectionError) -> HIDOTPConnection {
        try await HIDOTPConnection(device: device)
    }

    /// The HID device associated with this connection.
    public let device: HID.YubiKeyDevice

    var usbProductID: UInt16? { device.usbProductID }
    private let didClose = Promise<Error?>()

    private var locationID: Int { device.locationID }

    /// Opens the OTP interface of a device returned by ``availableDevices(matching:)``.
    public init(device: HID.YubiKeyDevice) async throws(OTPConnectionError) {
        guard !Task.isCancelled else { throw .cancelled }
        try await HIDOTPConnectionManager.shared.open(device: device, didClose: didClose)
        if Task.isCancelled {
            await HIDOTPConnectionManager.shared.close(
                locationID: device.locationID,
                didClose: didClose,
                error: OTPConnectionError.cancelled
            )
            throw .cancelled
        }
        self.device = device
    }
}

#endif
