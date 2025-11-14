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

/// HID device identification namespace.
///
/// Contains types for identifying and working with YubiKey HID devices.
enum HID {
    /// Represents a YubiKey device accessible via USB HID.
    ///
    /// Instances are returned by ``HIDFIDOConnection/availableDevices()`` and used to create
    /// connections with ``HIDFIDOConnection/init(device:)``.
    struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        /// The human-readable name of the YubiKey device.
        let name: String

        /// A textual representation of the YubiKey device.
        var description: String { name }

        // Private / Fileprivate
        fileprivate let locationID: Int

        fileprivate init(hidLocationID: Int, name: String) {
            self.locationID = hidLocationID
            self.name = name
        }
    }
}

/// A connection to the YubiKey utilizing USB HID for FIDO communication.
struct HIDFIDOConnection: Sendable, FIDOConnection {

    /// The HID device this connection is associated with.
    let device: HID.YubiKeyDevice

    /// Maximum packet size for HID reports.
    ///
    /// This value represents the maximum number of bytes that can be sent or received
    /// in a single packet via ``send(_:)`` or ``receive()``.
    let mtu = hidPayloadSize

    // Private / Fileprivate
    private var locationID: Int { device.locationID }

    /// Returns all available YubiKey devices connected via USB HID.
    ///
    /// - Returns: An array of ``HID/YubiKeyDevice`` instances representing connected YubiKeys.
    /// - Throws: ``FIDOConnectionError`` if device enumeration fails.
    static func availableDevices() async throws(FIDOConnectionError) -> [HID.YubiKeyDevice] {
        try await HIDConnectionManager.shared.availableDevices()
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits for a YubiKey to be connected via USB and establishes a FIDO connection to it.
    /// This method waits until a YubiKey becomes available.
    ///
    /// - Throws: ``FIDOConnectionError/noDevicesFound`` if no YubiKey is available.
    init() async throws(FIDOConnectionError) {
        guard let first = try await HIDFIDOConnection.availableDevices().first else {
            throw FIDOConnectionError.noDevicesFound
        }
        try await self.init(device: first)
    }

    /// Creates a new FIDO connection to a specific YubiKey device.
    ///
    /// Establishes a connection to the specified YubiKey device.
    ///
    /// - Parameter device: The ``HID.YubiKeyDevice`` to connect to.
    /// - Throws: ``FIDOConnectionError`` if the device cannot be accessed.
    init(device: HID.YubiKeyDevice) async throws(FIDOConnectionError) {
        try await HIDConnectionManager.shared.open(device: device)
        self.device = device
    }

    /// Creates a new FIDO connection to a specific YubiKey device.
    ///
    /// - Parameter device: The ``HID/YubiKeyDevice`` to connect to.
    /// - Returns: A fully-established connection ready for FIDO communication.
    /// - Throws: ``FIDOConnectionError`` if the device cannot be accessed.
    static func makeConnection(
        device: HID.YubiKeyDevice
    ) async throws(FIDOConnectionError) -> HIDFIDOConnection {
        try await HIDFIDOConnection(device: device)
    }

    /// Closes the connection to the YubiKey.
    ///
    /// - Parameter error: Optional error that caused the connection to close.
    func close(error: Error?) async {
        await HIDConnectionManager.shared.close(locationID: locationID, error: error)
    }

    /// Waits for the connection to close.
    ///
    /// - Returns: An error if the connection was closed due to an error, or `nil` if closed normally.
    func waitUntilClosed() async -> Error? {
        try? await HIDConnectionManager.shared.didClose(for: locationID).value()
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits for a YubiKey to be connected via USB and establishes a FIDO connection to it.
    /// This method waits until a YubiKey becomes available.
    ///
    /// - Returns: A fully–established connection ready for FIDO communication.
    /// - Throws: ``FIDOConnectionError/noDevicesFound`` if no YubiKey is available.
    static func makeConnection() async throws(FIDOConnectionError) -> HIDFIDOConnection {
        try await HIDFIDOConnection()
    }

    /// Sends a FIDO packet to the YubiKey.
    ///
    /// - Parameter packet: The packet data to send (must not exceed ``mtu`` bytes).
    /// - Throws: ``FIDOConnectionError`` if transmission fails.
    func send(_ packet: Data) async throws(FIDOConnectionError) {
        try await HIDConnectionManager.shared.sendPacket(packet, to: locationID)
    }

    /// Receives a FIDO packet from the YubiKey.
    ///
    /// - Returns: The received packet data (up to ``mtu`` bytes).
    /// - Throws: ``FIDOConnectionError`` if reception fails.
    func receive() async throws(FIDOConnectionError) -> Data {
        try await HIDConnectionManager.shared.receivePacket(from: locationID)
    }
}

// MARK: - Private helpers

// FIDO HID payload size
private let hidPayloadSize = 64

// HIDConnectionManager manages USB HID connections to FIDO devices.
// All operations run on a dedicated thread for IOKit compatibility.
private final class HIDConnectionManager: @unchecked Sendable, HasFIDOLogger {

    // MARK: - Singleton

    static let shared = HIDConnectionManager()
    private init() {
        // Start dedicated HID thread
        hidThread = Thread { [unowned self] in

            // Set thread name for debugging
            Thread.current.name = "HIDConnectionManager"

            // Store run loop reference
            runloop = CFRunLoopGetCurrent()

            // Initialize IOKit manager on this thread
            initializeHIDManager()

            // Signal that thread is ready
            startupSemaphore.signal()

            // Run the run loop to process HID events
            CFRunLoopRun()
        }

        hidThread?.start()

        // Wait for thread to start up
        startupSemaphore.wait()
    }

    // MARK: - Exposed Methods

    func availableDevices() async throws(FIDOConnectionError) -> [HID.YubiKeyDevice] {
        await runloop.perform {
            let devices = self.allDevicesInternal()
            let yubikeys = devices.compactMap { dev -> HID.YubiKeyDevice? in
                guard
                    let locationID = IOHIDDeviceGetProperty(dev, kIOHIDLocationIDKey as CFString) as? Int,
                    let name = IOHIDDeviceGetProperty(dev, kIOHIDProductKey as CFString) as? String
                else { return nil }
                return HID.YubiKeyDevice(hidLocationID: locationID, name: name)
            }
            /* Fix trace: self.trace(message: "found \(yubikeys.count) FIDO HID devices") */
            return yubikeys
        }
    }

    func didClose(for locationID: Int) async throws(FIDOConnectionError) -> Promise<Error?> {
        try await runloop.perform {
            guard let connectionState = self.openConnections[locationID] else {
                return .failure(FIDOConnectionError.connectionLost)
            }
            return .success(connectionState.didClose)
        }
    }

    func open(device: HID.YubiKeyDevice) async throws(FIDOConnectionError) {
        /* Fix trace: trace(message: "opening connection to \(device.name)") */
        try await runloop.perform {
            self.openDeviceInternal(device)
        }
        /* Fix trace: trace(message: "connection established to \(device.name)") */
    }

    func sendPacket(_ packet: Data, to locationID: Int) async throws(FIDOConnectionError) {
        /* Fix trace: trace(message: "sending \(packet.count) bytes") */
        try await runloop.perform {
            self.sendPacketInternal(packet, to: locationID)
        }
    }

    func receivePacket(from locationID: Int) async throws(FIDOConnectionError) -> Data {
        /* Fix trace: trace(message: "waiting for data") */
        let promise = try await runloop.perform {
            self.receivePacketInternal(from: locationID)
        }

        do {
            let data = try await promise.value()
            /* Fix trace: trace(message: "received \(data.count) bytes") */
            return data
        } catch {
            throw .receiveFailed("HID receive failed", error)
        }
    }

    func close(locationID: Int, error: Error?) async {
        /* Fix trace: trace(message: "closing connection, error: \(String(describing: error))") */
        await runloop.perform {
            self.closeInternal(locationID: locationID, error: error)
        }
    }

    // MARK: - HID Properties

    private let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))

    private let filter: [String: Any] = [
        kIOHIDDeviceUsagePageKey as String: 0xF1D0,
        kIOHIDDeviceUsageKey as String: 0x01,
    ]

    // Dictionary tracking open connections by location ID.
    private var openConnections = [Int: HIDConnectionState]()

    // MARK: - Thread Management

    private var hidThread: Thread?
    private var runloop: CFRunLoop!
    private let startupSemaphore = DispatchSemaphore(value: 0)

    // MARK: - HID Manager Initialization

    private func initializeHIDManager() {
        guard let runLoop = runloop else { return }

        IOHIDManagerSetDeviceMatching(manager, filter as CFDictionary)
        IOHIDManagerScheduleWithRunLoop(manager, runLoop, CFRunLoopMode.defaultMode.rawValue)

        // Device removed callback
        IOHIDManagerRegisterDeviceRemovalCallback(
            manager,
            { context, _, _, device in
                guard let ctx = context else { return }
                let me = Unmanaged<HIDConnectionManager>.fromOpaque(ctx).takeUnretainedValue()

                // Cancel pending I/O operations
                IOHIDDeviceCancel(device)

                // Remove from open connections and notify
                if let locationID = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int {
                    if let connection = me.openConnections[locationID] {
                        let promise = connection.didClose
                        Task { @Sendable in
                            await promise.fulfill(nil)
                        }
                        me.openConnections[locationID] = nil
                    }
                }
            },
            Unmanaged.passUnretained(self).toOpaque()
        )

        let openResult = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        guard openResult == kIOReturnSuccess else {
            /* Fix trace: trace(
                message:
                    "IOHIDManagerOpen failed with result: 0x\(String(format: "%08X", openResult)) – likely missing entitlements"
            ) */
            return
        }

        /* Fix trace: trace(message: "HID manager opened successfully") */
    }

    // MARK: - Internal HID Operations (Must run on HID thread)

    private func allDevicesInternal() -> [IOHIDDevice] {
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else {
            // No devices found (which is valid)
            return []
        }
        return Array(set)
    }

    private func openDeviceInternal(_ device: HID.YubiKeyDevice) -> Result<Void, FIDOConnectionError> {
        // Check if device is already connected
        if openConnections[device.locationID] != nil {
            /* Fix trace: trace(message: "device already connected – throwing .busy") */
            return .failure(.busy)
        }

        let allDevices = allDevicesInternal()
        let ioDevice = allDevices.first(where: {
            (IOHIDDeviceGetProperty($0, kIOHIDLocationIDKey as CFString) as? Int) == device.locationID
        })

        guard let ioDev = ioDevice else {
            /* Fix trace: trace(message: "failed to get HID device") */
            return .failure(.setupFailed("Failed to get HID device"))
        }

        let openResult = IOHIDDeviceOpen(ioDev, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
        guard openResult == kIOReturnSuccess else {
            /* Fix trace: trace(message: "IOHIDDeviceOpen failed with result: 0x\(String(format: "%08X", openResult))") */
            return .failure(.setupFailed("Failed to open HID device"))
        }

        // Create connection state
        let connectionState = HIDConnectionState(device: ioDev)

        // Register input report callback
        let context = Unmanaged.passUnretained(self).toOpaque()
        connectionState.inputBuffer.withUnsafeMutableBytes { bufferPtr in
            IOHIDDeviceRegisterInputReportCallback(
                ioDev,
                bufferPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                bufferPtr.count,
                inputReportCallback,
                context
            )
        }

        // Schedule device with run loop for callbacks
        IOHIDDeviceScheduleWithRunLoop(ioDev, runloop!, CFRunLoopMode.defaultMode.rawValue)

        openConnections[device.locationID] = connectionState
        /* Fix trace: trace(message: "device opened successfully") */

        return .success(())
    }

    private func closeInternal(locationID: Int, error: Error?) {
        guard let connectionState = openConnections.removeValue(forKey: locationID) else {
            /* Fix trace: trace(message: "no connection found") */
            return
        }

        // Unregister input report callback
        connectionState.inputBuffer.withUnsafeMutableBytes { bufferPtr in
            IOHIDDeviceRegisterInputReportCallback(
                connectionState.device,
                bufferPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                bufferPtr.count,
                nil,  // nil callback unregisters
                nil
            )
        }

        // Unschedule from run loop
        IOHIDDeviceUnscheduleFromRunLoop(connectionState.device, runloop!, CFRunLoopMode.defaultMode.rawValue)

        // Fulfill the promise
        let promise = connectionState.didClose
        Task { @Sendable in
            await promise.fulfill(error)
        }

        // Close the device
        IOHIDDeviceClose(connectionState.device, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
        /* Fix trace: trace(message: "device closed") */
    }

    private func sendPacketInternal(_ packet: Data, to locationID: Int) -> Result<Void, FIDOConnectionError> {
        guard packet.count <= hidPayloadSize else {
            /* Fix trace: trace(message: "packet too large: \(packet.count) > \(hidPayloadSize)") */
            return .failure(.transmitFailed("HID transmit failed"))
        }
        guard let connectionState = openConnections[locationID] else {
            /* Fix trace: trace(message: "no connection – throwing .connectionLost") */
            return .failure(.connectionLost)
        }
        let dev = connectionState.device

        // Send packet directly to HID device
        /* Fix trace: trace(message: "sending HID report directly (\(packet.count) bytes)") */
        let result = packet.withUnsafeBytes {
            IOHIDDeviceSetReport(
                dev,
                kIOHIDReportTypeOutput,
                0,
                $0.baseAddress!.assumingMemoryBound(to: UInt8.self),
                packet.count
            )
        }
        guard result == kIOReturnSuccess else {
            /* Fix trace: trace(message: "IOHIDDeviceSetReport failed with result: 0x\(String(format: "%08X", result))") */
            return .failure(.transmitFailed("HID transmit failed"))
        }

        return .success(())
    }

    private func receivePacketInternal(from locationID: Int) -> Result<Promise<Data>, FIDOConnectionError> {
        guard let connectionState = openConnections[locationID] else {
            return .failure(FIDOConnectionError.connectionLost)
        }

        // Check if we already have queued frames - deliver the oldest one immediately
        if !connectionState.receivedFrames.isEmpty {
            let frame = connectionState.receivedFrames.removeFirst()
            let promise = Promise<Data>()
            Task { @Sendable in
                await promise.fulfill(frame)
            }
            return .success(promise)
        }

        // No queued frames - create a new promise to wait for incoming data
        let promise = Promise<Data>()
        connectionState.pendingReceive = promise
        return .success(promise)
    }

    // MARK: - Connection State

    // Connection state for a single HID device
    private class HIDConnectionState {
        let device: IOHIDDevice
        let didClose: Promise<Error?>

        // Queue of received input reports waiting to be consumed
        var receivedFrames: [Data] = []

        // Promise for the next input report
        var pendingReceive: Promise<Data>?

        // HID input report buffer
        var inputBuffer = [UInt8](repeating: 0, count: hidPayloadSize)

        init(device: IOHIDDevice) {
            self.device = device
            self.didClose = Promise<Error?>()
        }
    }

    // Input report callback for HID devices
    private let inputReportCallback:
        @convention(c) (
            UnsafeMutableRawPointer?, IOReturn, UnsafeMutableRawPointer?, IOHIDReportType, UInt32,
            UnsafeMutablePointer<UInt8>, CFIndex
        ) -> Void = { context, result, sender, type, reportID, reportPtr, len in
            guard let context = context,
                result == kIOReturnSuccess,
                type == kIOHIDReportTypeInput
            else { return }

            let manager = Unmanaged<HIDConnectionManager>.fromOpaque(context).takeUnretainedValue()
            let reportData = Data(bytes: reportPtr, count: len)
            manager.handleInputReport(reportData, from: sender)
        }

    // MARK: - Callback Handlers

    // Handle input report from callback
    private func handleInputReport(_ data: Data, from sender: UnsafeMutableRawPointer?) {

        /* Fix trace: trace(message: "received input report of size \(data.count)") */
        guard data.count >= 1 else { return }
        // Find connection by matching the device pointer
        for (_, connectionState) in openConnections {
            if Unmanaged.passUnretained(connectionState.device).toOpaque() == sender {
                // If there's a pending receive promise, fulfill it immediately
                if let promise = connectionState.pendingReceive {
                    connectionState.pendingReceive = nil
                    // Return the full 64-byte HID report
                    Task { @Sendable in
                        await promise.fulfill(data)
                    }
                } else {
                    // No pending promise - queue the frame for later
                    connectionState.receivedFrames.append(data)
                }
                return
            }
        }

        /* Fix trace: trace(message: "received report for unknown device") */
    }
}

#endif  // os(macOS)
