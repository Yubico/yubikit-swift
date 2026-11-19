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

/// HID device identification namespace.
///
/// Contains types for identifying and working with YubiKey HID devices.
public enum HID {
    /// Represents a YubiKey device accessible via USB HID.
    ///
    /// Instances are returned by ``HIDFIDOConnection/availableDevices(matching:)`` and used to create
    /// connections with ``HIDFIDOConnection/makeConnection(device:)``.
    public struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        /// The human-readable name of the YubiKey device.
        public let name: String
        let usbProductID: UInt16?
        let usbVendorID: UInt16?

        /// A textual representation of the YubiKey device.
        public var description: String { name }

        /// The USB location shared by the FIDO and OTP interfaces of the same device.
        public let locationID: Int

        init(hidLocationID: Int, name: String, usbProductID: UInt16? = nil, usbVendorID: UInt16? = nil) {
            self.usbVendorID = usbVendorID
            self.usbProductID = usbProductID
            self.locationID = hidLocationID
            self.name = name
        }
    }
}

/// A connection to the YubiKey utilizing USB HID for FIDO communication.
public struct HIDFIDOConnection: Sendable, FIDOConnection {

    /// The HID device this connection is associated with.
    public let device: HID.YubiKeyDevice

    var usbProductID: UInt16? { device.usbProductID }

    /// Maximum packet size for HID reports.
    ///
    /// This value represents the maximum number of bytes that can be sent or received
    /// in a single packet via ``send(_:)`` or ``receive()``.
    public let mtu = hidPayloadSize

    // Private / Fileprivate
    private var locationID: Int { device.locationID }

    /// Returns all available YubiKey devices connected via USB HID.
    ///
    /// - Parameter matching: A case-insensitive substring, or `nil` for every YubiKey.
    /// - Returns: An array of ``HID/YubiKeyDevice`` instances representing connected YubiKeys.
    /// - Throws: ``FIDOConnectionError`` if device enumeration fails.
    public static func availableDevices(
        matching: String? = nil
    ) async throws(FIDOConnectionError) -> [HID.YubiKeyDevice] {
        let devices = try await HIDConnectionManager.shared.availableDevices()
        guard let matching else { return devices }
        return devices.filter { $0.name.localizedCaseInsensitiveContains(matching) }
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits until a YubiKey becomes available, then establishes a FIDO connection to it.
    ///
    /// - Throws: ``FIDOConnectionError/cancelled`` if the task is cancelled while waiting,
    ///   or another ``FIDOConnectionError`` if discovery or connection setup fails.
    public init() async throws(FIDOConnectionError) {
        let first = try await waitForDevice(cancellationError: FIDOConnectionError.cancelled) {
            () async throws(FIDOConnectionError) in
            try await Self.availableDevices()
        }
        try await self.init(device: first)
    }

    /// Creates a new FIDO connection to a specific YubiKey device.
    ///
    /// Establishes a connection to the specified YubiKey device.
    ///
    /// - Parameter device: A device returned by ``availableDevices(matching:)``.
    /// - Throws: ``FIDOConnectionError`` if the device cannot be accessed.
    public init(device: HID.YubiKeyDevice) async throws(FIDOConnectionError) {
        guard !Task.isCancelled else { throw .cancelled }
        try await HIDConnectionManager.shared.open(device: device)
        if Task.isCancelled {
            await HIDConnectionManager.shared.close(locationID: device.locationID, error: FIDOConnectionError.cancelled)
            throw .cancelled
        }
        self.device = device
    }

    /// Creates a new FIDO connection to a specific YubiKey device.
    ///
    /// - Parameter device: The ``HID/YubiKeyDevice`` to connect to.
    /// - Returns: A fully-established connection ready for FIDO communication.
    /// - Throws: ``FIDOConnectionError`` if the device cannot be accessed.
    public static func makeConnection(
        device: HID.YubiKeyDevice
    ) async throws(FIDOConnectionError) -> HIDFIDOConnection {
        try await HIDFIDOConnection(device: device)
    }

    /// Closes the connection to the YubiKey.
    ///
    /// - Parameter error: Optional error that caused the connection to close.
    public func close(error: Error?) async {
        await HIDConnectionManager.shared.close(locationID: locationID, error: error)
    }

    /// Waits for the connection to close.
    ///
    /// - Returns: An error if the connection was closed due to an error, or `nil` if closed normally.
    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for HID connection to close")
        let error = try? await HIDConnectionManager.shared.didClose(for: locationID).value()
        if let error {
            logger.debug(
                "HID connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("HID connection closed")
        }
        return error
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits until a YubiKey becomes available, then establishes a FIDO connection to it.
    ///
    /// - Returns: A fully–established connection ready for FIDO communication.
    /// - Throws: ``FIDOConnectionError/cancelled`` if the task is cancelled while waiting,
    ///   or another ``FIDOConnectionError`` if discovery or connection setup fails.
    public static func makeConnection() async throws(FIDOConnectionError) -> HIDFIDOConnection {
        try await HIDFIDOConnection()
    }

    /// Sends a FIDO packet to the YubiKey.
    ///
    /// - Parameter packet: The packet data to send (must not exceed ``mtu`` bytes).
    /// - Throws: ``FIDOConnectionError`` if transmission fails.
    public func send(_ packet: Data) async throws(FIDOConnectionError) {
        try await HIDConnectionManager.shared.sendPacket(packet, to: locationID)
    }

    /// Receives a FIDO packet from the YubiKey.
    ///
    /// - Returns: The received packet data (up to ``mtu`` bytes).
    /// - Throws: ``FIDOConnectionError`` if reception fails.
    public func receive() async throws(FIDOConnectionError) -> Data {
        try await HIDConnectionManager.shared.receivePacket(from: locationID)
    }
}

extension HIDFIDOConnection: HasFIDOLogger {}

let hidPayloadSize = 64

#endif
