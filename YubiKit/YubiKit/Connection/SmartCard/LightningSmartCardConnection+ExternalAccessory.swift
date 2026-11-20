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

#if os(iOS)

import Foundation
@preconcurrency import ExternalAccessory
import Logging

extension EAAccessoryWrapper: HasLightningLogger {}

// MARK: - Private helpers / extensions

protocol LightningAccessoryManaging: Sendable {
    func connectToCurrentDevices() async
    func startMonitoring() async
    func stopMonitoring() async
    func cleanupConnection(didClose: Promise<Error?>) async
    func transmit(didClose: Promise<Error?>, data: Data) async throws(SmartCardConnectionError) -> Data
}

actor LightningConnectionManager {

    static let shared = LightningConnectionManager(accessoryManager: EAAccessoryWrapper.shared)

    private let accessoryManager: any LightningAccessoryManaging
    private var pendingConnectionPromise: Promise<LightningSmartCardConnection>?
    private var connectionState: LightningSmartCardConnection?
    // Close and failed setup each block the next open until their accessory cleanup finishes.
    private var isCleaningUp = false

    init(accessoryManager: any LightningAccessoryManaging) {
        self.accessoryManager = accessoryManager
    }

    func connect() async throws(SmartCardConnectionError) -> LightningSmartCardConnection {
        guard !Task.isCancelled else { throw SmartCardConnectionError.cancelled }

        // If there is already a connection the caller must close the connection first.
        if connectionState != nil || pendingConnectionPromise != nil || isCleaningUp {
            logger.debug("Lightning connection is already active or pending")
            throw SmartCardConnectionError.busy
        }

        let connectionPromise: Promise<LightningSmartCardConnection> = .init()
        pendingConnectionPromise = connectionPromise

        // Otherwise, create and store a new connection task.
        let task = Task { () -> LightningSmartCardConnection in
            logger.debug("Waiting for a Lightning accessory")

            do {
                // Connect to YubiKeys that are already plugged in
                await accessoryManager.connectToCurrentDevices()

                // Start monitoring for new accessories
                await accessoryManager.startMonitoring()

                // Await the promise which will be fulfilled by accessoryDidConnect()
                let result = try await connectionPromise.value()
                logger.debug("Lightning connection established")
                self.pendingConnectionPromise = nil
                return result
            } catch {
                logger.debug(
                    "Lightning connection setup failed",
                    metadata: [
                        "errorType": .string(String(reflecting: type(of: error))),
                        "errorDomain": .string((error as NSError).domain),
                        "errorCode": .stringConvertible((error as NSError).code),
                    ]
                )
                // Cleanup on failure
                let state = self.connectionState
                self.connectionState = nil
                self.pendingConnectionPromise = nil
                self.isCleaningUp = true

                if let state {
                    await accessoryManager.cleanupConnection(didClose: state.didClose)
                    await state.didClose.fulfill(error)
                }
                await accessoryManager.stopMonitoring()
                self.isCleaningUp = false
                throw error
            }
        }

        do {
            return try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                Task { await self.cancelPendingConnection(connectionPromise) }
            }
        } catch {
            if Task.isCancelled { throw SmartCardConnectionError.cancelled }
            throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session", flatten: error)
        }
    }

    private func cancelPendingConnection(_ promise: Promise<LightningSmartCardConnection>) async {
        guard pendingConnectionPromise === promise, connectionState == nil else { return }
        await promise.cancel(with: SmartCardConnectionError.cancelled)
    }

    func transmit(
        request: Data,
        didClose: Promise<Error?>
    ) async throws(SmartCardConnectionError) -> Data {
        guard connectionState?.didClose === didClose else {
            logger.debug("Cannot send on a closed Lightning connection")
            throw SmartCardConnectionError.connectionLost
        }

        return try await accessoryManager.transmit(didClose: didClose, data: request)
    }

    func close(didClose: Promise<Error?>, error: Error?) async {
        guard let state = connectionState, state.didClose === didClose else { return }

        connectionState = nil
        isCleaningUp = true
        await accessoryManager.stopMonitoring()
        await accessoryManager.cleanupConnection(didClose: state.didClose)
        await state.didClose.fulfill(error)
        isCleaningUp = false
    }

    // Called by EAAccessoryWrapper when an accessory connects
    func accessoryDidConnect(didClose: Promise<Error?>) async {
        logger.debug("Lightning accessory connected")
        guard let promise = pendingConnectionPromise, connectionState == nil else {
            if connectionState?.didClose !== didClose {
                await accessoryManager.cleanupConnection(didClose: didClose)
            }
            return
        }

        let connection = LightningSmartCardConnection(didClose: didClose)
        connectionState = connection
        await promise.fulfill(connection)
    }

    // Called by EAAccessoryWrapper when an accessory disconnects
    func accessoryDidDisconnect(didClose: Promise<Error?>) async {
        logger.debug("Lightning accessory disconnected")

        guard let state = connectionState else {
            await pendingConnectionPromise?.cancel(with: SmartCardConnectionError.connectionLost)
            return
        }
        guard state.didClose === didClose else { return }
        connectionState = nil
        if let promise = pendingConnectionPromise {
            await promise.cancel(with: SmartCardConnectionError.connectionLost)
        }
        await state.didClose.fulfill(nil)
    }
}

private actor EAAccessoryWrapper: NSObject, StreamDelegate, LightningAccessoryManaging {

    static let shared = EAAccessoryWrapper()
    private override init() {}

    private let manager = EAAccessoryManager.shared()
    private struct Session {
        let didClose = Promise<Error?>()
        let accessory: EAAccessory
        let session: EASession
    }

    private var sessions: [ObjectIdentifier: Session] = [:]
    private var connectObserver: NSObjectProtocol?
    private var disconnectObserver: NSObjectProtocol?

    private func setupConnection(for accessory: EAAccessory) async {
        guard !sessions.values.contains(where: { $0.accessory.connectionID == accessory.connectionID }) else { return }
        guard let session = EASession(accessory: accessory, forProtocol: "com.yubico.ylp") else { return }
        let state = Session(accessory: accessory, session: session)
        sessions[ObjectIdentifier(state.didClose)] = state
        session.open()
        // Give streams time to stabilize.
        try? await Task.sleep(for: .milliseconds(100))
        guard sessions[ObjectIdentifier(state.didClose)] != nil else { return }
        session.outputStream?.delegate = self
        session.inputStream?.delegate = self
        await LightningConnectionManager.shared.accessoryDidConnect(didClose: state.didClose)
    }

    func cleanupConnection(didClose: Promise<Error?>) {
        guard let state = sessions.removeValue(forKey: ObjectIdentifier(didClose)) else { return }
        state.session.close()
        state.session.outputStream?.delegate = nil
        state.session.inputStream?.delegate = nil
    }

    private func disconnect(_ accessory: EAAccessory) async {
        guard let state = sessions.values.first(where: { $0.accessory.connectionID == accessory.connectionID })
        else { return }
        cleanupConnection(didClose: state.didClose)
        await LightningConnectionManager.shared.accessoryDidDisconnect(didClose: state.didClose)
    }

    func getConnectedYubiKeys() -> [EAAccessory] {
        manager.connectedAccessories.filter { $0.isYubiKey }
    }

    func connectToCurrentDevices() async {
        if let accessory = getConnectedYubiKeys().first {
            await setupConnection(for: accessory)
        }
    }

    func startMonitoring() {
        logger.debug("Starting Lightning accessory monitoring")
        // Prevent duplicate observers
        guard connectObserver == nil && disconnectObserver == nil else { return }

        connectObserver = NotificationCenter.default.addObserver(
            forName: .EAAccessoryDidConnect,
            object: manager,
            queue: nil
        ) { notification in
            guard let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory,
                accessory.isYubiKey
            else { return }
            Task { await EAAccessoryWrapper.shared.setupConnection(for: accessory) }
        }

        disconnectObserver = NotificationCenter.default.addObserver(
            forName: .EAAccessoryDidDisconnect,
            object: manager,
            queue: nil
        ) { notification in
            guard let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory,
                accessory.isYubiKey
            else { return }

            Task { await EAAccessoryWrapper.shared.disconnect(accessory) }
        }

        EAAccessoryManager.shared().registerForLocalNotifications()
    }

    func stopMonitoring() {
        logger.debug("Stopping Lightning accessory monitoring")
        if let observer = connectObserver {
            NotificationCenter.default.removeObserver(observer)
            connectObserver = nil
        }
        if let observer = disconnectObserver {
            NotificationCenter.default.removeObserver(observer)
            disconnectObserver = nil
        }
        EAAccessoryManager.shared().unregisterForLocalNotifications()
    }

    func transmit(didClose: Promise<Error?>, data: Data) async throws(SmartCardConnectionError) -> Data {
        guard let session = sessions[ObjectIdentifier(didClose)]?.session,
            let inputStream = session.inputStream,
            let outputStream = session.outputStream
        else { throw SmartCardConnectionError.connectionLost }

        // Append YLP iAP2 Signal
        do {
            logger.traceRequest(data)
            try outputStream.writeToYubiKey(data: Data([0x00]) + data)
        } catch {
            throw SmartCardConnectionError.transmitFailed("Lightning write failed", flatten: error)
        }

        while true {
            await sleepIgnoringCancellation(for: .milliseconds(2))
            let result: Data
            do {
                result = try inputStream.readFromYubiKey()
            } catch {
                throw SmartCardConnectionError.transmitFailed("Lightning read failed", flatten: error)
            }
            guard result.count >= 2 else {
                throw SmartCardConnectionError.malformedData("Response too short for status word")
            }
            logger.debug(
                "Received Lightning frame",
                metadata: [
                    "bytes": .stringConvertible(result.count), "status": .string(result.suffix(2).hexEncodedString),
                ]
            )
            let statusBytes = result.suffix(2)
            let status = Response.Status(sw1: statusBytes.first!, sw2: statusBytes.last!)

            // BUG #62 - Workaround for WTX == 0x01 while status is 0x9000 (success).
            if (status.status == Response.Status.Code.ok) || result.bytes[0] != 0x01 {
                if result.bytes[0] == 0x00 {  // Remove the YLP key protocol header
                    let response = result.subdata(in: 1..<result.count)
                    logger.traceResponse(response)
                    return response
                } else if result.bytes[0] == 0x01 {  // Remove the YLP key protocol header and the WTX
                    guard result.count >= 4 else {
                        throw SmartCardConnectionError.malformedData("Response too short to strip WTX header")
                    }
                    let response = result.subdata(in: 4..<result.count)
                    logger.traceResponse(response)
                    return response
                }
                throw SmartCardConnectionError.malformedData(
                    String(format: "Unexpected YLP header byte 0x%02X", result.bytes[0])
                )
            }
        }
    }

    nonisolated func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        logger.debug("Lightning stream event", metadata: ["event": .stringConvertible(eventCode.rawValue)])
    }
}

extension EAAccessory {
    fileprivate var isYubiKey: Bool {
        protocolStrings.contains("com.yubico.ylp") && manufacturer == "Yubico"
    }
}

extension EASession {
    // NOTE: Apple docs suggest streams should be opened on main thread when using RunLoop scheduling
    // However, since we're using polling-based I/O (not delegate callbacks), this may not be required
    fileprivate func open() {
        guard inputStream?.streamStatus != .open,
            outputStream?.streamStatus != .open,
            inputStream?.streamStatus != .opening,
            outputStream?.streamStatus != .opening
        else {
            assertionFailure("Tried to open streams that was already open or opening.")
            return
        }
        inputStream?.schedule(in: .main, forMode: .common)
        inputStream?.open()
        outputStream?.schedule(in: .main, forMode: .common)
        outputStream?.open()
    }

    fileprivate func close() {
        guard inputStream?.streamStatus != .closed,
            outputStream?.streamStatus != .closed
        else {
            assertionFailure("Tried to close streams that already was closed.")
            return
        }
        inputStream?.close()
        outputStream?.close()
    }
}

#endif
