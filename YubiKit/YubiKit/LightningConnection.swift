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
import ExternalAccessory

/// A connection to the YubiKey utilizing the Lightning port and External Accessory framework.
@available(iOS 16.0, *)
public final actor LightningConnection: Connection, InternalConnection {

    private static let manager = LightningConnectionManager()

    var _session: Session?
    func session() async -> Session? {
        return _session
    }
    func setSession(_ session: Session?) async {
        _session =  session
    }

    private let commandProcessingTime = 0.002;
    private var accessoryConnection: AccessoryConnection?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: (() -> Void)?

    private init() {}
    
    fileprivate init(connection: AccessoryConnection, closingHandler handler: @escaping () -> Void) {
        self.accessoryConnection = connection
        self.closingHandler = handler
    }

    // Starts lightning and wait for a connection
    public static func connection() async throws -> Connection {
        print("⚡️ LightningConnection, connection() called")
        return try await manager.connection()
    }
    
    public func close(error: Error?) async {
        closingHandler?()
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        accessoryConnection = nil
    }
    
    fileprivate func closedByManager(error: Error?) {
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        accessoryConnection = nil
    }
    
    public func connectionDidClose() async -> Error? {
        if accessoryConnection == nil {
            print("⚡️ LightningConnection, connectionDidClose() but no session so bailing out.")
            return nil
        }
        return await withCheckedContinuation { continuation in
            print("⚡️ LightningConnection, connectionDidClose() append closing continuation.")
            closingContinuations.append(continuation)
        }
    }
    
    internal func send(apdu: APDU) async throws -> Response {
        print("⚡️ LightningConnection, send() \(apdu).")
        guard let accessoryConnection, let outputStream = accessoryConnection.session.outputStream, let inputStream = accessoryConnection.session.inputStream else { throw "No current session" }
        var data = Data([0x00]) // YLP iAP2 Signal
        data.append(apdu.data)
        print("\(outputStream.streamStatus)")
        print("\(inputStream.streamStatus)")

        try outputStream.writeToYubiKey(data: data)
        while true {
            try await Task.sleep(for: .seconds(commandProcessingTime))
            let result = try inputStream.readFromYubiKey()
            if result.isEmpty { throw "Empty result" }
            let status = Response.StatusCode(data: result.subdata(in: result.count-2..<result.count))
            print("⚡️ LightningConnection, result (\(status)): \(result.hexEncodedString)")

            // BUG #62 - Workaround for WTX == 0x01 while status is 0x9000 (success).
            if (status == .ok) || result.bytes[0] != 0x01 {
                if result.bytes[0] == 0x00 { // Remove the YLP key protocol header
                    return Response(rawData: result.subdata(in: 1..<result.count))
                } else if result.bytes[0] == 0x01 { // Remove the YLP key protocol header and the WTX
                    return Response(rawData: result.subdata(in: 4..<result.count))
                }
                throw "Wrong response"
            }
        }
    }
    
    deinit {
        print("⚡️ deinit LightningConnection")
    }
}

fileprivate actor LightningConnectionManager {
    
    let accessoryWrapper = EAAccessoryWrapper()
    var currentConnection: LightningConnection?
    
    var connectionTask: Task<LightningConnection, Error>?
    func connection() async throws -> LightningConnection {
        let task = Task { [connectionTask] in
            connectionTask?.cancel() // Cancel any previous request for a connection
            return try await self._connection()
        }
        connectionTask = task
        let value = try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
        return value
    }
    
    private func _connection() async throws -> LightningConnection {
        print("⚡️ LightningConnectionManager, _connection()")
        
        if let currentConnection {
            await currentConnection.close(error: nil)
            self.currentConnection = nil
        }
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                accessoryWrapper.connection { result in
                    print("⚡️ LightningConnectionManager, _connection() got result: \(result), pass it to continuation: \(String(describing: continuation))")
                    print("⚡️ LightningConnectionManager, Task.isCancelled = \(Task.isCancelled)")
                    switch result {
                    case .success(let accessoryConnection):
                        let connection = LightningConnection(connection: accessoryConnection, closingHandler: { [weak self] in
                            self?.accessoryWrapper.stop()
                        })
                        self.currentConnection = connection
                        continuation.resume(returning: connection)
                        self.accessoryWrapper.connectionDidClose { error in
                            Task {
                                await connection.closedByManager(error: error)
                            }
                        }
                    case .failure(let error):
                        continuation.resume(throwing: error)
                        print("⚡️ LightningConnectionManager, remove \(String(describing: continuation)) after failure")
                    }
                }
            }
        } onCancel: {
            print("⚡️ LightningConnectionManager, onCancel called")
            accessoryWrapper.stop()
        }
    }
}

fileprivate struct AccessoryConnection: Equatable {
    let accessory: EAAccessory
    let session: EASession
    
    func open() {
        // Streams has to be opened and closed on the main thread to work
        DispatchQueue.main.sync {
            guard session.inputStream?.streamStatus != .open,
                  session.outputStream?.streamStatus != .open,
                  session.inputStream?.streamStatus != .opening,
                  session.outputStream?.streamStatus != .opening
            else {
                assertionFailure("Tried to open streams that was already open or opening.")
                return
            }
            session.inputStream?.schedule(in: .current, forMode: .common)
            session.inputStream?.open()
            session.outputStream?.schedule(in: .current, forMode: .common)
            session.outputStream?.open()
        }
    }
    
    func close() {
        DispatchQueue.main.sync {
            guard session.inputStream?.streamStatus != .closed,
                  session.outputStream?.streamStatus != .closed
            else {
                assertionFailure("Tried to close streams that already was closed.")
                return
            }
            session.inputStream?.close()
            session.outputStream?.close()
        }
    }
}

fileprivate class EAAccessoryWrapper: NSObject, StreamDelegate {
    
    private let manager = EAAccessoryManager.shared()
    private let queue = DispatchQueue(label: "com.yubico.eaAccessory-connection", qos: .background)
    
    enum State: Equatable {
        // no initiatingSession since accessory goes from monitoring straight to connected
        case ready, scanning, connected(AccessoryConnection)
    }
    private var state = State.ready
    
    private var connectingHandler: ((Result<AccessoryConnection, Error>) -> Void)?
    private var closingHandler: ((Error?) -> Void)?
    
    internal func connection(completion handler: @escaping (Result<AccessoryConnection, Error>) -> Void) {
        print("⚡️ EAAccessoryWrapper, schedule connection()")
        queue.async {
            print("⚡️ EAAccessoryWrapper, connection()")
            // Signal closure and cancel previous connection handlers
            // Swap out old handlers to the new ones
            self.closingHandler?("Closed by new call to connection()")
            self.closingHandler = nil
            self.connectingHandler?(.failure("⚡️ Cancelled by new call to connection()"))
            self.connectingHandler = handler
            
            if self.state == .ready {
                self.start()
            }
            
            // Connect to any YubiKeys that's already inserted into the device.
            guard let accessory = self.manager.connectedAccessories.filter({ accessory in
                accessory.isYubiKey
            }).first,
                  let connection = self.connectToKey(with: accessory) else { return }
            self.connectingHandler?(.success(connection))
            self.connectingHandler = nil
        }
    }
    
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        print("⚡️ EAAccessoryWrapper, Got stream event: \(eventCode) on stream: \(aStream)")
    }
    
    private func connectToKey(with accessory: EAAccessory) -> AccessoryConnection? {
        print("⚡️ EAAccessoryWrapper, connectToKey()")
        guard accessory.isYubiKey else { return nil }
        guard let session = EASession(accessory: accessory, forProtocol: "com.yubico.ylp") else { return nil }
        let connection = AccessoryConnection(accessory: accessory, session: session)
        print("⚡️ EAAccessoryWrapper, connected to: \(session)")
        
        connection.open()
        connection.session.outputStream!.delegate = self
        connection.session.inputStream!.delegate = self
        self.state = .connected(connection)
        return connection
    }
    
    internal func connectionDidClose(completion handler: @escaping (Error?) -> Void) {
        queue.async {
            print("⚡️ EAAccessoryWrapper, connectionDidClose()")
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    private func start() {
        print("⚡️ EAAccessoryWrapper, start()")
        self.queue.async {
            NotificationCenter.default.addObserver(forName: .EAAccessoryDidConnect,
                                                   object: self.manager,
                                                   queue: nil) { [weak self] notification in
                self?.queue.async {
                    print("⚡️ EAAccessoryWrapper, EAAccessoryDidConnect")
                    guard self?.state == .scanning,
                          self?.connectingHandler != nil,
                          let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory,
                          let connection = self?.connectToKey(with: accessory) else { return }
                    print("⚡️ EAAccessoryWrapper, did connect to key")
                    self?.state = .connected(connection)
                    self?.connectingHandler?(.success(connection))
                    self?.connectingHandler = nil
                }
            }
            NotificationCenter.default.addObserver(forName: .EAAccessoryDidDisconnect,
                                                   object: self.manager,
                                                   queue: nil) { [weak self] notification in
                self?.queue.async {
                    guard let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory else { return }
                    guard case let .connected(connection) = self?.state, connection.accessory.connectionID == accessory.connectionID else { return }
                    connection.close()
                    self?.closingHandler?(nil)
                    self?.closingHandler = nil
                    self?.state = .scanning
                }
            }
            EAAccessoryManager.shared().registerForLocalNotifications()
            // Only transition to .monitoring if previous state was .ready as we might already have transitioned to .connected if a YubiKey was inserted before we started.
            if self.state == .ready {
                self.state = .scanning
            }
        }
    }
    
    internal func stop() {
        print("⚡️ EAAccessoryWrapper, scheduled stop() with state = \(self.state) in \(Thread.current)")
        queue.async {
            print("⚡️ EAAccessoryWrapper, stop() with state = \(self.state) in \(Thread.current)")
            switch self.state {
            case .ready:
                break;
            case .scanning:
                // should we call the closingHandler as well?
                self.connectingHandler?(.failure("Cancelled from stop()"))
            case .connected(let connection):
                connection.close()
                self.closingHandler?("Closed by user")
            }
            self.connectingHandler = nil
            self.closingHandler = nil
            NotificationCenter.default.removeObserver(self, name: .EAAccessoryDidConnect, object: self.manager)
            NotificationCenter.default.removeObserver(self, name: .EAAccessoryDidDisconnect, object: self.manager)
            EAAccessoryManager.shared().unregisterForLocalNotifications()
            self.state = .ready
        }
    }
}

fileprivate extension EAAccessory {
    var isYubiKey: Bool {
        return self.protocolStrings.contains("com.yubico.ylp") && self.manufacturer == "Yubico"
    }
}

#endif
