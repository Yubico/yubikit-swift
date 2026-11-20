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

// HIDConnectionManager manages USB HID connections to FIDO devices.
// All operations run on a dedicated thread for IOKit compatibility.
final class HIDConnectionManager: @unchecked Sendable, HasFIDOLogger {

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

        hidThread?.qualityOfService = .userInitiated
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
                let pid = IOHIDDeviceGetProperty(dev, kIOHIDProductIDKey as CFString) as? Int
                let vid = IOHIDDeviceGetProperty(dev, kIOHIDVendorIDKey as CFString) as? Int
                return HID.YubiKeyDevice(
                    hidLocationID: locationID,
                    name: name,
                    usbProductID: pid.flatMap(UInt16.init(exactly:)),
                    usbVendorID: vid.flatMap(UInt16.init(exactly:))
                )
            }
            self.logger.debug("Enumerated FIDO HID devices", metadata: ["count": .stringConvertible(yubikeys.count)])
            return yubikeys
        }
    }

    func open(device: HID.YubiKeyDevice, lifetime: ConnectionLifetime) async throws(FIDOConnectionError) {
        logger.debug("Opening HID connection")
        try await runloop.perform {
            self.openDeviceInternal(device, lifetime: lifetime)
        }
        logger.debug("HID connection established")
    }

    func sendPacket(_ packet: Data, to locationID: Int, id: UUID) async throws(FIDOConnectionError) {
        logger.debug("Sending HID packet", metadata: ["bytes": .stringConvertible(packet.count)])
        try await runloop.perform {
            self.sendPacketInternal(packet, to: locationID, id: id)
        }
    }

    func receivePacket(from locationID: Int, id: UUID) async throws(FIDOConnectionError) -> Data {
        logger.debug("Waiting for HID packet")
        let promise = try await runloop.perform {
            self.receivePacketInternal(from: locationID, id: id)
        }

        do {
            let data = try await withTaskCancellationHandler {
                try await promise.value()
            } onCancel: {
                Task {
                    let withdrawn = await self.runloop.perform {
                        self.withdrawPendingReceive(promise, from: locationID, id: id)
                    }
                    await withdrawn?.cancel(with: FIDOConnectionError.cancelled)
                }
            }
            logger.debug("Received HID packet", metadata: ["bytes": .stringConvertible(data.count)])
            return data
        } catch let error as FIDOConnectionError {
            throw error
        } catch {
            throw .receiveFailed("HID receive failed", error)
        }
    }

    func close(locationID: Int, id: UUID, error: Error?) async {
        if let error {
            logger.debug(
                "Closing HID connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Closing HID connection")
        }
        await runloop.perform {
            self.closeInternal(locationID: locationID, id: id, error: error)
        }
    }

    // MARK: - HID Properties

    private let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))

    private let filter: [String: Any] = [
        kIOHIDVendorIDKey as String: 0x1050,
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

                // Remove from open connections and notify
                if let locationID = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int {
                    if let connection = me.openConnections[locationID], connection.device === device {
                        me.openConnections[locationID] = nil
                        me.logger.debug("HID device disconnected")
                        me.teardownConnection(connection, closeError: nil)
                    }
                }
            },
            Unmanaged.passUnretained(self).toOpaque()
        )

        let openResult = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        guard openResult == kIOReturnSuccess else {
            logger.warning("Failed to open HID manager", metadata: ["status": .stringConvertible(openResult)])
            return
        }

        logger.debug("HID manager opened")
    }

    // MARK: - Internal HID Operations (Must run on HID thread)

    private func allDevicesInternal() -> [IOHIDDevice] {
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else {
            // No devices found (which is valid)
            return []
        }
        return Array(set)
    }

    private func openDeviceInternal(
        _ device: HID.YubiKeyDevice,
        lifetime: ConnectionLifetime
    ) -> Result<Void, FIDOConnectionError> {
        // Check if device is already connected
        if openConnections[device.locationID] != nil {
            logger.debug("HID device is already connected")
            return .failure(.busy)
        }

        let allDevices = allDevicesInternal()
        let ioDevice = allDevices.first(where: {
            (IOHIDDeviceGetProperty($0, kIOHIDLocationIDKey as CFString) as? Int) == device.locationID
        })

        guard let ioDev = ioDevice else {
            logger.debug("HID device is no longer available")
            return .failure(.setupFailed("Failed to get HID device"))
        }

        let openResult = IOHIDDeviceOpen(ioDev, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
        guard openResult == kIOReturnSuccess else {
            logger.debug("Failed to open HID device", metadata: ["status": .stringConvertible(openResult)])
            return .failure(.setupFailed("Failed to open HID device"))
        }

        // Create connection state
        let connectionState = HIDConnectionState(device: ioDev, lifetime: lifetime)

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

        return .success(())
    }

    private func closeInternal(locationID: Int, id: UUID, error: Error?) {
        guard let connectionState = openConnections[locationID], connectionState.lifetime.id == id else {
            logger.debug("HID connection is already closed")
            return
        }

        openConnections[locationID] = nil
        teardownConnection(connectionState, closeError: error)
        IOHIDDeviceClose(connectionState.device, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
    }

    private func teardownConnection(_ connection: HIDConnectionState, closeError: Error?) {
        // Passing nil callback to IOHIDDeviceRegisterInputReportCallback unregisters it
        connection.inputBuffer.withUnsafeMutableBytes { bufferPtr in
            IOHIDDeviceRegisterInputReportCallback(
                connection.device,
                bufferPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                bufferPtr.count,
                nil,
                nil
            )
        }
        IOHIDDeviceUnscheduleFromRunLoop(connection.device, runloop!, CFRunLoopMode.defaultMode.rawValue)

        let didClose = connection.lifetime.didClose
        let pendingReceive = connection.packetQueue.cancelPendingReceive()
        Task { @Sendable in
            await pendingReceive?.cancel(with: FIDOConnectionError.connectionLost)
            await didClose.fulfill(closeError)
        }
    }

    private func sendPacketInternal(_ packet: Data, to locationID: Int, id: UUID) -> Result<Void, FIDOConnectionError> {
        guard packet.count <= hidPayloadSize else {
            logger.debug(
                "HID packet exceeds report size",
                metadata: ["bytes": .stringConvertible(packet.count), "maximum": .stringConvertible(hidPayloadSize)]
            )
            return .failure(.transmitFailed("HID transmit failed"))
        }
        guard let connectionState = openConnections[locationID], connectionState.lifetime.id == id else {
            logger.debug("Cannot send on a closed HID connection")
            return .failure(.connectionLost)
        }
        let dev = connectionState.device

        // Send packet directly to HID device
        logger.debug("Sending HID output report", metadata: ["bytes": .stringConvertible(packet.count)])
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
            logger.debug("HID report transmission failed", metadata: ["status": .stringConvertible(result)])
            return .failure(.transmitFailed("HID transmit failed"))
        }

        return .success(())
    }

    private func receivePacketInternal(from locationID: Int, id: UUID) -> Result<Promise<Data>, FIDOConnectionError> {
        guard let connectionState = openConnections[locationID], connectionState.lifetime.id == id else {
            return .failure(FIDOConnectionError.connectionLost)
        }

        return connectionState.packetQueue.receive()
    }

    private func withdrawPendingReceive(_ promise: Promise<Data>, from locationID: Int, id: UUID) -> Promise<Data>? {
        guard let state = openConnections[locationID], state.lifetime.id == id else { return nil }
        return state.packetQueue.withdraw(promise)
    }

    // MARK: - Connection State

    // Connection state for a single HID device
    private class HIDConnectionState {
        let device: IOHIDDevice
        let lifetime: ConnectionLifetime

        let packetQueue = HIDPacketQueue()

        // HID input report buffer
        var inputBuffer = [UInt8](repeating: 0, count: hidPayloadSize)

        init(device: IOHIDDevice, lifetime: ConnectionLifetime) {
            self.device = device
            self.lifetime = lifetime
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
        logger.debug("Received HID input report", metadata: ["bytes": .stringConvertible(data.count)])

        guard data.count >= 1 else { return }
        // Find connection by matching the device pointer
        for (_, connectionState) in openConnections {
            if Unmanaged.passUnretained(connectionState.device).toOpaque() == sender {
                if let promise = connectionState.packetQueue.enqueue(data) {
                    // Return the full 64-byte HID report
                    Task { @Sendable in
                        await promise.fulfill(data)
                    }
                }
                return
            }
        }

        logger.debug("Ignoring HID report for an unknown device")
    }
}

// Only the HID manager's run loop mutates this queue.
final class HIDPacketQueue {
    private var receivedFrames: [Data] = []
    private var pendingReceive: Promise<Data>?

    func receive() -> Result<Promise<Data>, FIDOConnectionError> {
        guard pendingReceive == nil else { return .failure(.busy) }

        let promise = Promise<Data>()
        if !receivedFrames.isEmpty {
            let frame = receivedFrames.removeFirst()
            Task { @Sendable in await promise.fulfill(frame) }
        } else {
            pendingReceive = promise
        }
        return .success(promise)
    }

    func withdraw(_ promise: Promise<Data>) -> Promise<Data>? {
        guard pendingReceive === promise else { return nil }
        pendingReceive = nil
        return promise
    }

    func enqueue(_ frame: Data) -> Promise<Data>? {
        guard let promise = pendingReceive else {
            receivedFrames.append(frame)
            return nil
        }
        pendingReceive = nil
        return promise
    }

    func cancelPendingReceive() -> Promise<Data>? {
        defer { pendingReceive = nil }
        return pendingReceive
    }
}

#endif  // os(macOS)
