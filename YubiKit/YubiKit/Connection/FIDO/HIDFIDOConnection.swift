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

/// HIDFIDOConnection specific errors
/* public */ enum HIDFIDOConnectionError: Error, Sendable {
    /// IOKit HID manager is not supported or failed to initialize
    case unsupported
    /// No FIDO HID devices available
    case noAvailableDevices
    /// Failed to get the HID device
    case getDeviceFailed
    /// Failed to open HID device session
    case beginSessionFailed
}

// Used to identify a device / connection.
// Exposed when calling `HIDFIDOConnection.availableDevices`
// and when creating a connection with HIDFIDOConnection.connection(device:)
/* public */ enum HIDFIDO {
    /* public */ struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        /* public */ let name: String
        /* public */ var description: String { name }

        // Private / Fileprivate
        fileprivate let locationID: Int

        fileprivate init(hidLocationID: Int, name: String) {
            self.locationID = hidLocationID
            self.name = name
        }
    }
}

/// A connection to the YubiKey utilizing USB HID for FIDO communication.
/* public */ struct HIDFIDOConnection: Sendable, FIDOConnection {

    /// Maximum packet size for HID reports
    /* public */ let mtu = hidPayloadSize

    // Private / Fileprivate
    private let locationID: Int

    /* public */ static var availableDevices: [HIDFIDO.YubiKeyDevice] {
        get async throws {
            try await HIDFIDOConnectionManager.shared.availableDevices()
        }
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits for a YubiKey to be connected via USB and establishes a FIDO connection to it.
    /// This method waits until a YubiKey becomes available.
    ///
    /// - Throws: ``HIDFIDOConnectionError.noAvailableDevices`` if no YubiKey is available.
    /* public */ init() async throws {
        guard let first = try await HIDFIDOConnection.availableDevices.first else {
            throw HIDFIDOConnectionError.noAvailableDevices
        }
        try await self.init(device: first)
    }

    /// Creates a new FIDO connection to a specific YubiKey device.
    ///
    /// Establishes a connection to the specified YubiKey device.
    ///
    /// - Parameter device: The ``HIDFIDO.YubiKeyDevice`` to connect to.
    /// - Throws: Connection errors if the device cannot be accessed.
    /* public */ init(device: HIDFIDO.YubiKeyDevice) async throws {
        try await HIDFIDOConnectionManager.shared.open(device: device)
        self.locationID = device.locationID
    }

    /* public */ static func connection(device: HIDFIDO.YubiKeyDevice) async throws -> HIDFIDOConnection {
        try await HIDFIDOConnection(device: device)
    }

    /* public */ func close(error: Error?) async {
        await HIDFIDOConnectionManager.shared.close(locationID: locationID, error: error)
    }

    /* public */ func connectionDidClose() async -> Error? {
        try? await didClose.value()
    }

    /// Creates a new FIDO connection to the first available YubiKey.
    ///
    /// Waits for a YubiKey to be connected via USB and establishes a FIDO connection to it.
    /// This method waits until a YubiKey becomes available.
    ///
    /// - Returns: A fully–established connection ready for FIDO communication.
    /// - Throws: ``HIDFIDOConnectionError.noAvailableDevices`` if no YubiKey is available.
    /* public */ static func connection() async throws -> HIDFIDOConnection {
        try await HIDFIDOConnection()
    }

    /* public */ func send(_ packet: Data) async throws {
        try await HIDFIDOConnectionManager.shared.sendPacket(packet, to: locationID)
    }

    /* public */ func receive() async throws -> Data {
        try await HIDFIDOConnectionManager.shared.receivePacket(from: locationID)
    }

    private var didClose: Promise<Error?> {
        get async throws {
            try await HIDFIDOConnectionManager.shared.didClose(for: locationID)
        }
    }

}

// MARK: - Private helpers

// FIDO HID payload size
private let hidPayloadSize = 64

// HIDFIDOConnectionManager manages USB HID connections to FIDO devices.
// All operations run on a dedicated thread for IOKit compatibility.
private final class HIDFIDOConnectionManager: @unchecked Sendable, HasFIDOLogger {

    // MARK: - Singleton

    static let shared = HIDFIDOConnectionManager()
    private init() {
        // Start dedicated HID thread
        hidThread = Thread { [unowned self] in

            // Set thread name for debugging
            Thread.current.name = "HIDFIDOConnectionManager"

            // Store run loop reference
            hidRunLoop = CFRunLoopGetCurrent()

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

    func availableDevices() async throws -> [HIDFIDO.YubiKeyDevice] {
        try await performAsync {
            let devices = try self.allDevicesInternal()
            let yubikeys = devices.compactMap { dev -> HIDFIDO.YubiKeyDevice? in
                guard let locationID = IOHIDDeviceGetProperty(dev, kIOHIDLocationIDKey as CFString) as? Int,
                    let name = IOHIDDeviceGetProperty(dev, kIOHIDProductKey as CFString) as? String
                else { return nil }
                return HIDFIDO.YubiKeyDevice(hidLocationID: locationID, name: name)
            }
            self.trace(message: "found \(yubikeys.count) FIDO HID devices")
            return yubikeys
        }
    }

    func didClose(for locationID: Int) async throws -> Promise<Error?> {
        try await performAsync {
            guard let connectionState = self.openConnections[locationID] else {
                throw ConnectionError.noConnection
            }
            return connectionState.didClose
        }
    }

    func open(device: HIDFIDO.YubiKeyDevice) async throws {
        trace(message: "opening connection to \(device.name)")
        try await performAsync {
            try self.openDeviceInternal(device)
        }
        trace(message: "connection established to \(device.name)")
    }

    func sendPacket(_ packet: Data, to locationID: Int) async throws {
        trace(message: "sending \(packet.count) bytes")
        try await performAsync {
            try self.sendPacketInternal(packet, to: locationID)
        }
    }

    func receivePacket(from locationID: Int) async throws -> Data {
        trace(message: "waiting for data")
        let promise = try await performAsync {
            try self.receivePacketInternal(from: locationID)
        }
        let data = try await promise.value()
        trace(message: "received \(data.count) bytes")
        return data
    }

    func close(locationID: Int, error: Error?) async {
        trace(message: "closing connection, error: \(String(describing: error))")
        await performAsync {
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
    private var hidRunLoop: CFRunLoop?
    private let startupSemaphore = DispatchSemaphore(value: 0)

    private func perform(_ work: @Sendable @escaping () -> Void) {
        guard let runLoop = hidRunLoop else {
            fatalError("HID thread not started")
        }

        CFRunLoopPerformBlock(runLoop, CFRunLoopMode.defaultMode.rawValue, work)
        CFRunLoopWakeUp(runLoop)
    }

    private func performAsync<T>(_ work: @Sendable @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            perform {
                do {
                    let result = try work()
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func performAsync(_ work: @Sendable @escaping () -> Void) async {
        await withCheckedContinuation { continuation in
            perform {
                work()
                continuation.resume()
            }
        }
    }

    // MARK: - HID Manager Initialization

    private func initializeHIDManager() {
        guard let runLoop = hidRunLoop else { return }

        IOHIDManagerSetDeviceMatching(manager, filter as CFDictionary)
        IOHIDManagerScheduleWithRunLoop(manager, runLoop, CFRunLoopMode.defaultMode.rawValue)

        // Device removed callback
        IOHIDManagerRegisterDeviceRemovalCallback(
            manager,
            { context, _, _, device in
                guard let ctx = context else { return }
                let me = Unmanaged<HIDFIDOConnectionManager>.fromOpaque(ctx).takeUnretainedValue()

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
            trace(
                message:
                    "IOHIDManagerOpen failed with result: 0x\(String(format: "%08X", openResult)) – likely missing entitlements"
            )
            return
        }

        trace(message: "HID manager opened successfully")
    }

    // MARK: - Internal HID Operations (Must run on HID thread)

    private func allDevicesInternal() throws -> [IOHIDDevice] {
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else {
            // No devices found (which is valid)
            return []
        }
        return Array(set)
    }

    private func openDeviceInternal(_ device: HIDFIDO.YubiKeyDevice) throws {
        // Check if device is already connected
        if openConnections[device.locationID] != nil {
            trace(message: "device already connected – throwing .busy")
            throw ConnectionError.busy
        }

        let allDevices = try allDevicesInternal()
        let ioDevice = allDevices.first(where: {
            (IOHIDDeviceGetProperty($0, kIOHIDLocationIDKey as CFString) as? Int) == device.locationID
        })

        guard let ioDev = ioDevice else {
            trace(message: "failed to get HID device")
            throw HIDFIDOConnectionError.getDeviceFailed
        }

        let openResult = IOHIDDeviceOpen(ioDev, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
        guard openResult == kIOReturnSuccess else {
            trace(message: "IOHIDDeviceOpen failed with result: 0x\(String(format: "%08X", openResult))")
            throw HIDFIDOConnectionError.beginSessionFailed
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
        IOHIDDeviceScheduleWithRunLoop(ioDev, hidRunLoop!, CFRunLoopMode.defaultMode.rawValue)

        openConnections[device.locationID] = connectionState
        trace(message: "device opened successfully")
    }

    private func closeInternal(locationID: Int, error: Error?) {
        guard let connectionState = openConnections.removeValue(forKey: locationID) else {
            trace(message: "no connection found")
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
        IOHIDDeviceUnscheduleFromRunLoop(connectionState.device, hidRunLoop!, CFRunLoopMode.defaultMode.rawValue)

        // Fulfill the promise
        let promise = connectionState.didClose
        Task { @Sendable in
            await promise.fulfill(error)
        }

        // Close the device
        IOHIDDeviceClose(connectionState.device, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
        trace(message: "device closed")
    }

    private func sendPacketInternal(_ packet: Data, to locationID: Int) throws {
        guard packet.count <= hidPayloadSize else {
            trace(message: "packet too large: \(packet.count) > \(hidPayloadSize)")
            throw ConnectionError.unexpectedResult
        }
        guard let connectionState = openConnections[locationID] else {
            trace(message: "no connection – throwing .noConnection")
            throw ConnectionError.noConnection
        }
        let dev = connectionState.device

        // Send packet directly to HID device
        trace(message: "sending HID report directly (\(packet.count) bytes)")
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
            trace(message: "IOHIDDeviceSetReport failed with result: 0x\(String(format: "%08X", result))")
            throw ConnectionError.unexpectedResult
        }
    }

    private func receivePacketInternal(from locationID: Int) throws -> Promise<Data> {
        guard let connectionState = openConnections[locationID] else {
            throw ConnectionError.noConnection
        }

        // Create a new promise for this receive operation
        let promise = Promise<Data>()
        connectionState.pendingReceive = promise
        return promise
    }

    // MARK: - Connection State

    // Connection state for a single HID device
    private class HIDConnectionState {
        let device: IOHIDDevice
        let didClose: Promise<Error?>

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

            let manager = Unmanaged<HIDFIDOConnectionManager>.fromOpaque(context).takeUnretainedValue()
            let reportData = Data(bytes: reportPtr, count: len)
            manager.handleInputReport(reportData, from: sender)
        }

    // MARK: - Callback Handlers

    // Handle input report from callback
    private func handleInputReport(_ data: Data, from sender: UnsafeMutableRawPointer?) {

        trace(message: "received input report of size \(data.count)")
        guard data.count >= 1 else { return }
        // Find connection by matching the device pointer
        for (_, connectionState) in openConnections {
            if Unmanaged.passUnretained(connectionState.device).toOpaque() == sender {
                // Fulfill pending receive promise if there is one
                if let promise = connectionState.pendingReceive {
                    connectionState.pendingReceive = nil
                    // Return the full 64-byte HID report
                    Task { @Sendable in
                        await promise.fulfill(data)
                    }
                }
                return
            }
        }

        trace(message: "received report for unknown device")
    }
}

#endif  // os(macOS)
