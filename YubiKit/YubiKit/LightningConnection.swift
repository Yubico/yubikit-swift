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
import OSLog

/// A connection to the YubiKey utilizing the Lightning port and External Accessory framework.
@available(iOS 16.0, *)
public final actor LightningConnection: Connection {

    private static let manager = LightningConnectionManager()

    private let commandProcessingTime = 0.002;
    private var accessoryConnection: AccessoryConnection?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: (() -> Void)?

    private init() {}
    
    fileprivate init(connection: AccessoryConnection, closingHandler handler: @escaping () -> Void) {
        self.accessoryConnection = connection
        self.closingHandler = handler
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
    }

    // Starts lightning and wait for a connection
    public static func connection() async throws -> Connection {
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
        return try await manager.connection()
    }
    
    public func close(error: Error?) async {
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
        closingHandler?()
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        accessoryConnection = nil
    }
    
    fileprivate func closedByManager(error: Error?) {
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        accessoryConnection = nil
    }
    
    public func connectionDidClose() async -> Error? {
        if accessoryConnection == nil {
            return nil
        }
        return await withCheckedContinuation { continuation in
            closingContinuations.append(continuation)
        }
    }
    
    private var processor: Processor? = nil
    internal func getProcessor() async -> Processor? {
        return processor
    }
    internal func setProcessor(_ processor: Processor?) async {
        self.processor = processor
    }
    
    public func send(data: Data) async throws -> Data {
        guard let accessoryConnection, let outputStream = accessoryConnection.session.outputStream, let inputStream = accessoryConnection.session.inputStream else { throw ConnectionError.noConnection }
        // Append YLP iAP2 Signal
        try outputStream.writeToYubiKey(data: Data([0x00]) + data)
        while true {
            try await Task.sleep(for: .seconds(commandProcessingTime))
            let result = try inputStream.readFromYubiKey()
            Logger.lightning.debug("\(String(describing: self).lastComponent) \(#function): readFromYubiKey: \(result.hexEncodedString)")
            guard result.count >= 2 else { throw ConnectionError.missingResult }
            let status = ResponseStatus(data: result.subdata(in: result.count-2..<result.count))

            // BUG #62 - Workaround for WTX == 0x01 while status is 0x9000 (success).
            if (status.status == .ok) || result.bytes[0] != 0x01 {
                if result.bytes[0] == 0x00 { // Remove the YLP key protocol header
                    return result.subdata(in: 1..<result.count)
                } else if result.bytes[0] == 0x01 { // Remove the YLP key protocol header and the WTX
                    return result.subdata(in: 4..<result.count)
                }
                throw ConnectionError.unexpectedResult
            }
        }
    }
    
    deinit {
        Logger.lightning.debug("\(String(describing: self).lastComponent) \(#function)")
    }
}

fileprivate actor LightningConnectionManager {
    
    let accessoryWrapper = EAAccessoryWrapper()
    var currentConnection: LightningConnection?
    
    var connectionTask: Task<LightningConnection, Error>?
    func connection() async throws -> LightningConnection {
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
        let task = Task { [connectionTask] in
            if let connectionTask {
                Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function): a function call is already awaiting a connection, cancel it before proceeding.")
                connectionTask.cancel()
            }
            return try await self._connection()
        }
        connectionTask = task
        let value = try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function): returned: \(String(describing: value))")
        return value
    }
    
    private func _connection() async throws -> LightningConnection {
        Logger.lightning.debug("\(String(describing: self).lastComponent), \(#function)")
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
                    }
                }
            }
        } onCancel: {
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
        Logger.lightning.debug("EAAccessoryWrapper, \(#function)")
        queue.async {
            // Signal closure and cancel previous connection handlers
            // Swap out old handlers to the new ones
            self.closingHandler?(ConnectionError.closed)
            self.closingHandler = nil
            self.connectingHandler?(.failure(ConnectionError.cancelled))
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
        Logger.lightning.debug("EAAccessoryWrapper, \(#function): Got stream event: \(String(describing: eventCode)) on stream: \(aStream)")
    }
    
    private func connectToKey(with accessory: EAAccessory) -> AccessoryConnection? {
        guard accessory.isYubiKey else { return nil }
        guard let session = EASession(accessory: accessory, forProtocol: "com.yubico.ylp") else { return nil }
        let connection = AccessoryConnection(accessory: accessory, session: session)
        Logger.lightning.debug("EAAccessoryWrapper, \(#function), connected to: \(session)")
        connection.open()
        connection.session.outputStream!.delegate = self
        connection.session.inputStream!.delegate = self
        self.state = .connected(connection)
        return connection
    }
    
    internal func connectionDidClose(completion handler: @escaping (Error?) -> Void) {
        queue.async {
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    private func start() {
        self.queue.async {
            NotificationCenter.default.addObserver(forName: .EAAccessoryDidConnect,
                                                   object: self.manager,
                                                   queue: nil) { [weak self] notification in
                self?.queue.async {
                    guard self?.state == .scanning,
                          self?.connectingHandler != nil,
                          let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory,
                          let connection = self?.connectToKey(with: accessory) else { return }
                    Logger.lightning.debug("EAAccessoryWrapper, connected to: \(accessory)")
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
        queue.async {
            switch self.state {
            case .ready:
                break;
            case .scanning:
                // should we call the closingHandler as well?
                self.connectingHandler?(.failure(ConnectionError.cancelled))
            case .connected(let connection):
                connection.close()
                self.closingHandler?(ConnectionError.closed)
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
