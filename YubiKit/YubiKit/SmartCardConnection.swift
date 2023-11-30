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

import Foundation
import CryptoTokenKit
import OSLog

/// A connection to the YubiKey utilizing the USB-C port and the TKSmartCard implementation from
/// the CryptoTokenKit framework.
@available(iOS 16.0, macOS 13.0, *)
public final actor SmartCardConnection: Connection, InternalConnection {
    
    private static let manager = SmartCardManager()
    
    public static func connection() async throws -> Connection {
        Logger.smartCard.debug(#function)
        return try await manager.connection()
    }
    
    private weak var _session: Session?
    func session() async -> Session? {
        return _session
    }
    func setSession(_ session: Session?) async {
        _session =  session
    }

    private var smartCard: TKSmartCard?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: (() -> Void)?
    
    private init() { }
    
    fileprivate init(smartCard: TKSmartCard, closingHandler handler: @escaping () -> Void) {
        self.smartCard = smartCard
        self.closingHandler = handler
    }
    
    public func close(error: Error?) async {
        Logger.smartCard.debug(#function)
        closingHandler?()
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        smartCard = nil
    }
    
    fileprivate func closedByManager(error: Error?) {
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        closingContinuations.removeAll()
        smartCard = nil
    }
    
    // Wait for the connection to close
    public func connectionDidClose() async -> Error? {
        if smartCard == nil {
            return nil
        }
        return await withCheckedContinuation { continuation in
            closingContinuations.append(continuation)
        }
    }
    
    internal func send(apdu: APDU) async throws -> Response {
        guard let smartCard else { throw ConnectionError.noConnection }
        let data = try await smartCard.transmit(apdu.data)
        return Response(rawData: data)
    }
    
    deinit {
        Logger.smartCard.debug(#function)
    }
}


fileprivate actor SmartCardManager {
    
    let smartCardWrapper = TKSmartCardWrapper()
    var currentConnection: SmartCardConnection?
    
    var connectionTask: Task<SmartCardConnection, Error>?
    func connection() async throws -> SmartCardConnection {
        let task = Task { [connectionTask] in
            if let connectionTask {
                Logger.smartCard.debug("A call to connection() is already awaiting a connection, cancel it before proceeding.")
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
        Logger.smartCard.debug("returned: \(String(describing: value))")
        return value
    }
    
    // Only allow one connect() at a time
    private func _connection() async throws -> SmartCardConnection {
        
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
                smartCardWrapper.connection { result in
                    switch result {
                    case .success(let smartCard):
                        let connection = SmartCardConnection(smartCard: smartCard, closingHandler: { [weak self] in
                            self?.smartCardWrapper.stop()
                        })
                        self.currentConnection = connection
                        continuation.resume(returning: connection)
                        self.smartCardWrapper.connectionDidClose { error in
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
            smartCardWrapper.stop()
        }
    }
    
    func didDisconnect() async -> Error? {
        return await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in // try to remove variable definition in the future
            smartCardWrapper.connectionDidClose { error in
                continuation.resume(returning: error)
            }
        }
    }
}


fileprivate class TKSmartCardWrapper {
    
    private let manager = TKSmartCardSlotManager.default
    private let queue = DispatchQueue(label: "com.yubico.tkSmartCard-connection", qos: .background)

    enum State: Equatable {
        case ready, monitoring, initatingSession, connected(TKSmartCard)
    }
    private var state = State.ready
    
    private var connectingHandler: ((Result<TKSmartCard, Error>) -> Void)?
    private var closingHandler: ((Error?) -> Void)?
    
    private var managerObservation: NSKeyValueObservation?
    private var slotObservation: NSKeyValueObservation?
    
    internal func connection(completion handler: @escaping (Result<TKSmartCard, Error>) -> Void) {
        queue.async {
            // Signal closure and cancel previous connection handlers
            // Swap out old handlers to the new ones
            self.closingHandler?(ConnectionError.closed)
            self.closingHandler = nil
            self.connectingHandler?(.failure(ConnectionError.cancelled))
            self.connectingHandler = handler

            // If we're currently not monitoring or initating a session
            switch self.state {
            case .ready:
                break
            case .connected(let smartCard):
                smartCard.endSession()
            case .monitoring, .initatingSession:
                return
            }

            assert(self.manager != nil, "🪪 No default TKSmartCardSlotManager, check entitlements for com.apple.smartcard.")
            if let slotName = self.manager?.slotNames.first, let slot = self.manager?.slotNamed(slotName), slot.state == .validCard {
                self.state = .monitoring
                self.beginSession(withSlot: slot)
            } else {
                // Observe new connection and its subsequent disconnect
                self.observeManagerChanges()
            }
        }
    }
    
    internal func connectionDidClose(completion handler: @escaping (Error?) -> Void) {
        queue.async {
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    private func observeManagerChanges() {
        self.queue.async {
            self.state = .monitoring
            self.managerObservation = self.manager?.observe(\.slotNames) { [weak self] manager, value in
                guard let self else { return }
                self.queue.async {
                    // If slotNames is empty the TKSmartCard did disconnect
                    if manager.slotNames.isEmpty {
                        self.closingHandler?(nil)
                        self.closingHandler = nil
                        self.state = .ready
                        return
                    }
                    
                    // We got at least one connected slot, lets observe changes to that slot
                    if self.connectingHandler != nil, let slotName = manager.slotNames.first {
                        manager.getSlot(withName: slotName) { slot in
                            guard let slot else {
                                self.state = .ready
                                self.connectingHandler?(.failure(SmartCardConnectionError.getSmartCardSlotFailed))
                                self.connectingHandler = nil
                                return
                            }
                            if slot.state == .validCard {
                                self.beginSession(withSlot: slot)
                            } else {
                                self.slotObservation = slot.observe(\TKSmartCardSlot.state) { [weak self] slot, value in
                                    self?.queue.async {
                                        if slot.state == .validCard {
                                            self?.beginSession(withSlot: slot)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    private func observeKeyRemoval() {
        self.managerObservation = self.manager?.observe(\.slotNames) { [weak self] manager, value in
            guard let self else { return }
            self.queue.async {
                // If slotNames is empty the TKSmartCard did disconnect
                if manager.slotNames.isEmpty {
                    self.closingHandler?(nil) // should we signal an error?
                    self.closingHandler = nil
                    self.state = .ready
                    return
                }
            }
        }
    }
    
    private func beginSession(withSlot slot: TKSmartCardSlot) {
        queue.async {
            guard self.state != .initatingSession else { return }
            self.state = .initatingSession
            Logger.smartCard.debug("TKSmartCardWrapper, initiatingSession for slot: \(slot)")
            if let smartCard = slot.makeSmartCard() {
                smartCard.beginSession { [weak self] success, error in
                    self?.queue.async {
                        guard self?.state == .initatingSession else { // If state is not .initiatingSession stop() has been called.
                            smartCard.endSession()
                            return
                        }
                        if success {
                            self?.state = .connected(smartCard)
                            self?.connectingHandler?(.success(smartCard))
                            self?.connectingHandler = nil
                            self?.observeKeyRemoval()
                        } else {
                            self?.state = .ready
                            self?.connectingHandler?(.failure(SmartCardConnectionError.beginSessionFailed))
                            self?.connectingHandler = nil
                        }
                    }
                }
            }
        }
    }
    
    // Stop monitoring and return to ready state and if connected end the TKSmartCard session.
    internal func stop() {
        queue.async {
            switch self.state {
            case .ready:
                break;
            case .monitoring, .initatingSession:
                // should we call the closingHandler as well?
                self.connectingHandler?(.failure(ConnectionError.cancelled))
            case .connected(let session):
                session.endSession()
                self.closingHandler?(ConnectionError.closed)
            }
            self.state = .ready
            self.connectingHandler = nil
            self.closingHandler = nil
            self.slotObservation?.invalidate()
            self.slotObservation = nil
            self.managerObservation?.invalidate()
            self.managerObservation = nil
        }
    }
}

/// SmartCardConnection specific errors
public enum SmartCardConnectionError: Error {
    /// CryptoTokenKit failed to return a TKSmartCardSlot.
    case getSmartCardSlotFailed
    /// CryptoTokenKit failed to start a session for the TKSmartCard.
    case beginSessionFailed
}
