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
import OSLog

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
    /// Only one connection can exist at a time - attempting to create another will throw ``ConnectionError/busy``.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection() async throws(SmartCardConnectionError) -> LightningSmartCardConnection {
        trace(message: "requesting new connection")
        return try await LightningSmartCardConnection()
    }

    public func close(error: Error?) async {
        trace(message: "closing connection")
        await LightningConnectionManager.shared.close(for: self, error: error)
    }

    public func waitUntilClosed() async -> Error? {
        trace(message: "awaiting dismissal")
        let error = await LightningConnectionManager.shared.didClose(for: self)
        if let error {
            trace(message: "dismissed, error: \(String(describing: error))")
        } else {
            trace(message: "dismissed")
        }
        return error
    }

    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        trace(message: "\(data.count) bytes")
        let response = try await LightningConnectionManager.shared.transmit(request: data, for: self)
        trace(message: "received \(response.count) bytes")
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
            throw SmartCardConnectionError.busy
        }

        // Otherwise, create and store a new connection task.
        let task = Task { () -> LightningConnectionID in
            trace(message: "begin new connection task")

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
                trace(message: "connection established")
                self.pendingConnectionPromise = nil
                return result
            } catch {
                trace(message: "connection failed: \(error.localizedDescription)")
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
            throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session", error)
        }
    }

    func transmit(
        request: Data,
        for connection: LightningSmartCardConnection
    ) async throws(SmartCardConnectionError) -> Data {
        let connectionID = connection.accessoryConnectionID
        trace(message: "\(request.count) bytes to connection \(connectionID)")

        guard let state = connectionState,
            state.connectionID == connectionID
        else {
            trace(message: "noConnection")
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
        trace(message: "accessory connected with ID \(connectionID)")
        guard let promise = pendingConnectionPromise else { return }

        connectionState = (connectionID: connectionID, didCloseConnection: Promise<Error?>())
        await promise.fulfill(connectionID)
    }

    // Called by EAAccessoryWrapper when an accessory disconnects
    func accessoryDidDisconnect(connectionID: LightningConnectionID) async {
        trace(message: "accessory disconnected with ID \(connectionID)")

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
        trace(message: "opening session for ID \(id)")
        session.open()
        // Give streams time to stabilize
        try? await Task.sleep(for: .milliseconds(100))
        session.outputStream?.delegate = self
        session.inputStream?.delegate = self

        sessions[id] = session
    }

    func cleanupConnection(id: LightningConnectionID) {
        trace(message: "closing session for ID \(id)")
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
        trace(message: "begin monitoring")
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
        trace(message: "stop monitoring")
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
            try outputStream.writeToYubiKey(data: Data([0x00]) + data)
        } catch {
            throw SmartCardConnectionError.transmitFailed("Lightning write failed", error)
        }

        while true {
            try? await Task.sleep(for: .seconds(0.002))
            let result: Data
            do {
                result = try inputStream.readFromYubiKey()
            } catch {
                throw SmartCardConnectionError.transmitFailed("Lightning read failed", error)
            }
            trace(
                message:
                    "got \(result.count) bytes, SW: \(String(format:"%02X%02X", result.bytes[result.count-2], result.bytes[result.count-1]))"
            )
            guard result.count >= 2 else { throw SmartCardConnectionError.connectionLost }
            let status = ResponseStatus(data: result.subdata(in: result.count - 2..<result.count))

            // BUG #62 - Workaround for WTX == 0x01 while status is 0x9000 (success).
            if (status.status == ResponseStatus.StatusCode.ok) || result.bytes[0] != 0x01 {
                if result.bytes[0] == 0x00 {  // Remove the YLP key protocol header
                    return result.subdata(in: 1..<result.count)
                } else if result.bytes[0] == 0x01 {  // Remove the YLP key protocol header and the WTX
                    return result.subdata(in: 4..<result.count)
                }
                throw SmartCardConnectionError.connectionLost
            }
        }
    }

    nonisolated func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        trace(message: "stream event: \(String(describing: eventCode))")
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
