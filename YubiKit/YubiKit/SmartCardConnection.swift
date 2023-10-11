//
//  SmartCardConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-06-21.
//

import Foundation
import CryptoTokenKit


public final actor SmartCardConnection: Connection, InternalConnection {
    
    private static let manager = SmartCardManager()
    
    public static func connection() async throws -> Connection {
        print("🪪 SmartCardConnection, connection() on \(Thread.current)")
        return try await manager.connection()
    }
    
    var _session: Session?
    func session() async -> Session? {
        return _session
    }
    func setSession(_ session: Session?) async {
        _session =  session
    }

    private var smartCard: TKSmartCard?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: (() -> Void)?
    
    fileprivate init(smartCard: TKSmartCard, closingHandler handler: @escaping () -> Void) {
        self.smartCard = smartCard
        self.closingHandler = handler
    }
    
    private init() { }
    
    deinit {
        print("🪪 deinit SmartCardConnection")
    }
    
    public func close(signalClosure: Bool, error: Error?) async {
        print("🪪 SmartCardConnection, close in thread \(Thread.current)")
        closingHandler?()
        closingContinuations.forEach { continuation in
            continuation.resume(returning: error)
        }
        print("🪪 SmartCardConnection, messaged all continuations, let remove them in thread \(Thread.current)")
        closingContinuations.removeAll()
        print("🪪 SmartCardConnection, endSession() for \(smartCard)")
        smartCard = nil
    }
    
    // Wait for the connection to close
    public func connectionDidClose() async -> Error? {
        print("🪪 SmartCardConnection, await connectionDidClose() called in thread \(Thread.current)")
        if smartCard == nil {
            print("🪪 SmartCardConnection, await connectionDidClose() baling out since connection is already closed")
            return nil
        }
        return await withCheckedContinuation { continuation in
            print("🪪 SmartCardConnection, append closingContinuation in thread \(Thread.current)")
            closingContinuations.append(continuation)
        }
    }
    
    // Send apdu over connection
    public func send(apdu: APDU) async throws -> Response {
        print("🪪 SmartCardConnection, send(apdu: \(apdu))")
        guard let smartCard else { throw "No SmartCard connection" }
        let data = try await smartCard.transmit(apdu.data)
        return Response(rawData: data)
    }
}


fileprivate actor SmartCardManager {
    
    let smartCardWrapper = TKSmartCardWrapper()
    var currentConnection: SmartCardConnection?
    var continuation: CheckedContinuation<SmartCardConnection, Error>?
    var connectionTask: Task<SmartCardConnection, Error>?
    
    func connection() async throws -> SmartCardConnection {
        let task = Task { [connectionTask] in
            connectionTask?.cancel() // Cancel any previous request for a connection
            return try await self._connection()
        }
        connectionTask = task
        return try await task.value
    }
    
    // Only allow one connect() at a time
    private func _connection() async throws -> SmartCardConnection {
        print("🪪 SmartCardManagerActor, _connection()")
        
        if let currentConnection {
            await currentConnection.close(signalClosure: false, error: nil)
            self.currentConnection = nil
        }
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else { 
                    continuation.resume(throwing: CancellationError())
                    return
                }
                print("🪪 SmartCardManagerActor, will call manager.connectSmartCard() Task.isCancelled = \(Task.isCancelled)")
                smartCardWrapper.connection { result in
                    print("🪪 SmartCardManagerActor, _connection() got result \(result) pass it to \(self.continuation)")
                    print("🪪 SmartCardManagerActor, Task.isCancelled = \(Task.isCancelled)")
                    switch result {
                    case .success(let smartCard):
                        let connection = SmartCardConnection(smartCard: smartCard, closingHandler: { [weak self] in
                            self?.smartCardWrapper.stop()
                        })
                        self.currentConnection = connection
                        continuation.resume(returning: connection)
                    case .failure(let error):
                        continuation.resume(throwing: error)
                        print("🪪 SmartCardManagerActor, remove \(self.continuation) after failure")
                    }
                }
            }
        } onCancel: {
            print("SmartCardManagerActor onCancel: called on \(Thread.current)")
            smartCardWrapper.stop()
        }
    }
    
    func didDisconnect() async -> Error? {
        return await withTaskCancellationHandler {
            return await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in // try to remove variable definition in the future
                smartCardWrapper.connectionDidClose { error in
                    continuation.resume(returning: error)
                }
            }
        } onCancel: {
            print("SmartCardManagerActor didDisconnect(), onCancel: called on \(Thread.current)")
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
            print("🪪 SmartCardManager, connectSmartCard()")
            // Signal closure and cancel previous connection handlers
            // Swap out old handlers to the new ones
            self.closingHandler?("Closed by new call to connectSmartCard()")
            self.closingHandler = nil
            self.connectingHandler?(.failure("🪪 Cancelled by new call to connectSmartCard()"))
            self.connectingHandler = handler

            // If we're currently not monitoring or initating a session
            switch self.state {
            case .ready:
                print("🪪 SmartCardManager, state == .ready ")
                break
            case .connected(let smartCard):
                smartCard.endSession()
                print("🪪 SmartCardManager, state == .connected. Call endSession()")
            case .monitoring, .initatingSession:
                print("🪪 SmartCardManager, manager is already monitoring or initiating a new session. Bail out.")
                return
            }

            assert(self.manager != nil, "🪪 No default TKSmartCardSlotManager, check entitlements for com.apple.smartcard.")
            if let slotName = self.manager?.slotNames.first, let slot = self.manager?.slotNamed(slotName), slot.state == .validCard {
                print("🪪 SmartCardManager, a smartcard was already connected, start session with slot \(slot)")
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
            print("🪪 SmartCardManager, connectionDidClose()")
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    private func observeManagerChanges() {
        self.queue.async {
            print("🪪 SmartCardManager, Start observing changes in slot manager")
            self.state = .monitoring
            self.managerObservation = self.manager?.observe(\.slotNames) { [weak self] manager, value in
                guard let self else { return }
                self.queue.async {
                    print("🪪 SmartCardManager, Got changes in slotNames: \(value)")
                    // If slotNames is empty the TKSmartCard did disconnect
                    if manager.slotNames.isEmpty {
                        print("🪪 SmartCardManager, TKSmartCardSlot removed")
                        self.closingHandler?(nil)
                        self.closingHandler = nil
                        self.state = .ready
                        return
                    }
                    
                    // We got at least one connected slot, lets observe changes to that slot
                    if self.connectingHandler != nil, let slotName = manager.slotNames.first {
                        manager.getSlot(withName: slotName) { slot in
                            guard let slot else { fatalError("Throw proper error here") }
                            if slot.state == .validCard {
                                self.beginSession(withSlot: slot)
                            } else {
                                print("🪪 SmartCardManager, Start observing changes to the current TKSmartCardSlot")
                                self.slotObservation = slot.observe(\TKSmartCardSlot.state) { [weak self] slot, value in
                                    self?.queue.async {
                                        print("🪪 SmartCardManager, TKSmartCardSlot.state changed to: \(slot.state)")
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
                print("🪪 SmartCardManager, Got changes in slotNames: \(value)")
                // If slotNames is empty the TKSmartCard did disconnect
                if manager.slotNames.isEmpty {
                    print("🪪 SmartCardManager, TKSmartCardSlot removed")
                    self.closingHandler?(nil)
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
            print("🪪 SmartCardManager, beginSession \(slot), state = \(self.state)")
            if let smartCard = slot.makeSmartCard() {
                smartCard.beginSession { [weak self] success, error in
                    self?.queue.async {
                        print("🪪 SmartCardManager, beginSession returned \(success), error = \(error)")
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
                            self?.connectingHandler?(.failure("🪪 Failed but got no error!"))
                            self?.connectingHandler = nil
                        }
                    }
                }
            }
        }
    }
    
    // Stop monitoring and return to ready state and if connected end the TKSmartCard session.
    internal func stop() {
        print("🪪 SmartCardManager, stop() with state = \(state) in \(Thread.current)")
        queue.async {
            switch self.state {
            case .ready, .initatingSession:
                break;
            case .monitoring:
                self.connectingHandler?(.failure("Cancelled from stop()"))
            case .connected(let session):
                session.endSession()
                self.closingHandler?("Closed by user")
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
