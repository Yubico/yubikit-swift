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

/// A connection to the YubiKey utilizing the Lightning port and External Accessory framework.
@available(iOS 16.0, *)
public struct LightningSmartCardConnection: SmartCardConnection, Sendable {
    fileprivate let accessoryConnectionID: LightningConnectionID

    /// Creates a new Lightning connection to a YubiKey.
    ///
    /// Waits for a YubiKey to be connected via Lightning port and establishes a connection.
    ///
    /// - Throws: ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        accessoryConnectionID = try await LightningConnectionManager.shared.connect()
    }

    /// Creates a connection to a YubiKey via Lightning port.
    ///
    /// > Warning: Connections must be explicitly closed using ``close(error:)``.
    /// Only one connection can exist at a time - attempting to create another will throw ``SmartCardConnectionError/busy``.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection() async throws(SmartCardConnectionError) -> LightningSmartCardConnection {
        logger.debug("Requesting Lightning connection")
        return try await LightningSmartCardConnection()
    }

    public func close(error: Error?) async {
        if let error {
            logger.debug(
                "Closing Lightning connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Closing Lightning connection")
        }
        await LightningConnectionManager.shared.close(for: self, error: error)
    }

    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for Lightning connection to close")
        let error = await LightningConnectionManager.shared.didClose(for: self)
        if let error {
            logger.debug(
                "Lightning connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Lightning connection closed")
        }
        return error
    }

    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        logger.debug("Sending Lightning request", metadata: ["bytes": .stringConvertible(data.count)])
        let response = try await LightningConnectionManager.shared.transmit(request: data, for: self)
        logger.debug("Received Lightning response", metadata: ["bytes": .stringConvertible(response.count)])
        return response
    }

}

// MARK: - Internal helpers / extensions

// Downcast helper
extension SmartCardConnection {
    public var lightningConnection: LightningSmartCardConnection? {
        self as? LightningSmartCardConnection
    }
}

extension LightningSmartCardConnection: HasLightningLogger {}
extension LightningConnectionManager: HasLightningLogger {}
extension EAAccessoryWrapper: HasLightningLogger {}

// MARK: - Private helpers / extensions

private actor LightningConnectionManager {

    static let shared = LightningConnectionManager()

    private var pendingConnectionPromise: Promise<LightningConnectionID>?
    private var connectionState: (connectionID: LightningConnectionID, didCloseConnection: (Promise<Error?>))?

    private init() {}

    func connect() async throws(SmartCardConnectionError) -> LightningConnectionID {
        // If there is already a connection the caller must close the connection first.
        if connectionState != nil || pendingConnectionPromise != nil {
            logger.debug("Lightning connection is already active or pending")
            throw SmartCardConnectionError.busy
        }

        // Otherwise, create and store a new connection task.
        let task = Task { () -> LightningConnectionID in
            logger.debug("Waiting for a Lightning accessory")

            do {
                // Close previous connection if it exists
                if let connection = connectionState {
                    await connection.didCloseConnection.fulfill(nil)
                    self.connectionState = nil
                }

                // Create a promise to bridge the callback from EAAccessoryWrapper
                let connectionPromise: Promise<LightningConnectionID> = .init()
                self.pendingConnectionPromise = connectionPromise

                // Connect to YubiKeys that are already plugged in
                await EAAccessoryWrapper.shared.connectToCurrentDevices()

                // Start monitoring for new accessories
                await EAAccessoryWrapper.shared.startMonitoring()

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
                self.pendingConnectionPromise = nil
                self.connectionState = nil
                await EAAccessoryWrapper.shared.stopMonitoring()
                throw error
            }
        }

        do {
            return try await task.value
        } catch {
            throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session", flatten: error)
        }
    }

    func transmit(
        request: Data,
        for connection: LightningSmartCardConnection
    ) async throws(SmartCardConnectionError) -> Data {
        let connectionID = connection.accessoryConnectionID

        guard let state = connectionState,
            state.connectionID == connectionID
        else {
            logger.debug("Cannot send on a closed Lightning connection")
            throw SmartCardConnectionError.connectionLost
        }

        return try await EAAccessoryWrapper.shared.transmit(id: connectionID, data: request)
    }

    func close(for connection: LightningSmartCardConnection, error: Error?) async {
        guard let state = connectionState,
            state.connectionID == connection.accessoryConnectionID
        else { return }

        await EAAccessoryWrapper.shared.stopMonitoring()
        await EAAccessoryWrapper.shared.cleanupConnection(id: state.connectionID)
        await state.didCloseConnection.fulfill(error)
        connectionState = nil
    }

    func didClose(for connection: LightningSmartCardConnection) async -> Error? {
        guard let state = connectionState,
            state.connectionID == connection.accessoryConnectionID
        else { return nil }

        return try? await state.didCloseConnection.value()
    }

    // Called by EAAccessoryWrapper when an accessory connects
    func accessoryDidConnect(connectionID: LightningConnectionID) async {
        logger.debug("Lightning accessory connected")
        guard let promise = pendingConnectionPromise else { return }

        connectionState = (connectionID: connectionID, didCloseConnection: Promise<Error?>())
        await promise.fulfill(connectionID)
    }

    // Called by EAAccessoryWrapper when an accessory disconnects
    func accessoryDidDisconnect(connectionID: LightningConnectionID) async {
        logger.debug("Lightning accessory disconnected")

        // If a connection attempt is in progress, fail it.
        if let promise = pendingConnectionPromise {
            await promise.cancel(with: SmartCardConnectionError.connectionLost)
            self.pendingConnectionPromise = nil
        }

        guard let state = connectionState,
            state.connectionID == connectionID
        else { return }

        await state.didCloseConnection.fulfill(nil)
        connectionState = nil
    }
}

private actor EAAccessoryWrapper: NSObject, StreamDelegate {

    static let shared = EAAccessoryWrapper()
    private override init() {}

    private let manager = EAAccessoryManager.shared()
    private var sessions: [LightningConnectionID: EASession] = [:]
    private var connectObserver: NSObjectProtocol?
    private var disconnectObserver: NSObjectProtocol?

    func setupConnection(id: LightningConnectionID, session: EASession) async {
        logger.debug("Opening Lightning session")
        session.open()
        // Give streams time to stabilize
        try? await Task.sleep(for: .milliseconds(100))
        session.outputStream?.delegate = self
        session.inputStream?.delegate = self

        sessions[id] = session
    }

    func cleanupConnection(id: LightningConnectionID) {
        logger.debug("Closing Lightning session")
        guard let session = sessions[id] else { return }

        session.close()
        session.outputStream?.delegate = nil
        session.inputStream?.delegate = nil

        sessions[id] = nil
    }

    func getConnectedYubiKeys() -> [EAAccessory] {
        manager.connectedAccessories.filter { $0.isYubiKey }
    }

    func connectToCurrentDevices() async {
        // Check for already-connected YubiKeys
        let connectedYubiKeys = getConnectedYubiKeys()
        if let connectedKey = connectedYubiKeys.first {

            let connectionID: LightningConnectionID = connectedKey.connectionID

            // Check if we already have a session for this accessory
            if let _ = sessions[connectionID] {
                // Reuse existing session
                await LightningConnectionManager.shared.accessoryDidConnect(connectionID: connectionID)
            } else if let session = EASession(accessory: connectedKey, forProtocol: "com.yubico.ylp") {
                // Create new session for this accessory
                await setupConnection(id: connectionID, session: session)
                await LightningConnectionManager.shared.accessoryDidConnect(connectionID: connectionID)
            }
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
                accessory.isYubiKey,
                let session = EASession(accessory: accessory, forProtocol: "com.yubico.ylp")
            else { return }

            let connectionID: LightningConnectionID = accessory.connectionID

            Task {
                await EAAccessoryWrapper.shared.setupConnection(id: connectionID, session: session)
                await LightningConnectionManager.shared.accessoryDidConnect(connectionID: connectionID)
            }
        }

        disconnectObserver = NotificationCenter.default.addObserver(
            forName: .EAAccessoryDidDisconnect,
            object: manager,
            queue: nil
        ) { notification in
            guard let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory,
                accessory.isYubiKey
            else { return }

            let connectionID: LightningConnectionID = accessory.connectionID

            Task {
                await EAAccessoryWrapper.shared.cleanupConnection(id: connectionID)
                await LightningConnectionManager.shared.accessoryDidDisconnect(connectionID: connectionID)
            }
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

    func transmit(id: LightningConnectionID, data: Data) async throws(SmartCardConnectionError) -> Data {
        guard let session = sessions[id],
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
            try? await Task.sleep(for: .seconds(0.002))
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

private typealias LightningConnectionID = Int

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
