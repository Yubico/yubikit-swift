//
//  SmartCardConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-06-21.
//

import Foundation
import CryptoTokenKit


public final class SmartCardConnection: Connection, InternalConnection {
    
    private static var connection: SmartCardConnection?
    private static let manager = SmartCardManager()
    private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()
    private static var connectingLock = NSLock()
    private static var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private static var closingLock = NSLock()

    internal var session: Session?
    private var smartCard: TKSmartCard
    
    private init(smartCard: TKSmartCard) {
        self.smartCard = smartCard
    }
    
    // A Connection is not a true singleton as it will be dealloced once the connection has been closed.
    @MainActor public static func connection() async throws -> Connection {
        print("🪪 SmartCardConnection connection() called")
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                connectingLock.with {
                    if let connection = self.connection {
                        print("🪪 Reuse SmartCardConnection")
                        continuation.resume(returning: connection)
                        return
                    }
                    
                    if Self.connectionContinuations.isEmpty {
                        print("🪪 No current connection in progress, let start a new one.")
                        connectionContinuations.append(continuation)
                        manager.connect { result in
                            print("🪪 Got result, now wait for lock")
                            switch result {
                            case .success(let smartCard):
                                let connection = SmartCardConnection(smartCard: smartCard)
                                Self.connection = connection
                                print("🪪 Loop through continuations (\(connectionContinuations.count)) and send connection")
                                connectionContinuations.forEach { continuation in
                                    print("🪪 Send connection \(connection) to continuation \(continuation)")
                                    continuation.resume(returning: connection)
                                    print("🪪 did send connection")
                                }
                                connectionContinuations.removeAll()
                            case .failure(let error):
                                connectionContinuations.forEach { continuation in
                                    continuation.resume(throwing: error)
                                }
                                print("🪪 Got error \(error), clear continuations \(connectionContinuations.count).")
                                connectionContinuations.removeAll()
                            }
                        }
                    } else {
                        connectionContinuations.append(continuation)
                    }
                }
            }
        } onCancel: {
            connectingLock.with {
                // we should probably only cancel the continuation associated with this 
                print("🪪 Cancel all continuations \(connectionContinuations.count)!")
                connectionContinuations.forEach { continuation in
                    continuation.resume(throwing: CancellationError())
                }
                manager.endSession()
                connectionContinuations.removeAll()
            }
        }
    }

    public func close() {
        smartCard.endSession()
    }
    
    public func connectionDidClose() async -> Error? {
        return await withTaskCancellationHandler {
            return await withCheckedContinuation { continuation in
                Self.closingLock.with {
                    Self.connection = nil
                    if Self.closingContinuations.isEmpty {
                        Self.closingContinuations.append(continuation)
                        Self.manager.connectionDidClose { error in
                            Self.closingContinuations.forEach { $0.resume(returning: error) }
                            Self.closingContinuations.removeAll()
                        }
                    } else {
                        Self.closingContinuations.append(continuation)
                    }
                }
            }
        } onCancel: {
            Self.closingLock.with {
                print("🪪 Cancel connectionDidClose()")
                Self.closingContinuations.forEach { continuation in
                    continuation.resume(returning: CancellationError())
                }
                Self.closingContinuations.removeAll()
                // should we end the session when the close task is cancelled?
                Self.manager.endSession()
            }
        }
    }
    
    public func send(apdu: APDU) async throws -> Response {
        let data = try await smartCard.transmit(apdu.data)
        return Response(rawData: data)
    }
}


fileprivate class SmartCardManager {
    
    private let manager = TKSmartCardSlotManager.default
    private var currrentSlot: TKSmartCardSlot?
    private var currentSmartCard: TKSmartCard?
    private var connectingCallback: ((Result<TKSmartCard, Error>) -> Void)? = nil
    private var closingCallback: ((Error?) -> Void)? = nil
    private var managerObservation: NSKeyValueObservation?
    private var slotObservation: NSKeyValueObservation?

    internal func connect(_ callback: @escaping (Result<TKSmartCard, Error>) -> Void) {
        guard connectingCallback == nil else {
            fatalError("🪪 Connecting callback already registered!")
        }

        guard let manager else {
            callback(.failure("🪪 No default TKSmartCardSlotManager, check entitlemenst for com.apple.smartcard."))
            return
        }
        
        self.connectingCallback = callback
        
        if let slotName = manager.slotNames.first, let slot = manager.slotNamed(slotName), slot.state == .validCard {
            beginSession(withSlot: slot)
        } else {
            // Observe new connection and its subsequent disconnect
            self.observeManagerChanges()
        }
        
    }
    
    internal func connectionDidClose(_ callback: @escaping (Error?) -> Void) {
        guard closingCallback == nil else {
            fatalError("🪪 Closing callback already registered!")
        }
        closingCallback = callback
    }
    
    // 1. waiting for initial connection OR 2. already connected and waiting for disconnect
    private func observeManagerChanges() {
        managerObservation = manager?.observe(\TKSmartCardSlotManager.slotNames) { [weak self] manager, value in
            print("🪪 Got changes in slotNames: \(value)")
            if manager.slotNames.isEmpty {
                // shouuld this be done in observeSlotChanges?
                print("🪪 TKSmartCardSlot removed")
                self?.closingCallback?(nil)
                self?.currrentSlot = nil
                self?.closingCallback = nil
                return
            }
            if self?.connectingCallback != nil, let slotName = manager.slotNames.first {
                manager.getSlot(withName: slotName) { slot in
                    print("🪪 Got a slot from \(slotName)")
                    self?.observeSlotChanges(slot: slot!)
                }
            }
        }
    }

    private func observeSlotChanges(slot: TKSmartCardSlot) {
        print("🪪 Start observing changes to the current TKSmartCardSlot")
        currrentSlot = slot
        if slot.state == .validCard {
            beginSession(withSlot: slot)
        } else {
            slotObservation = currrentSlot?.observe(\TKSmartCardSlot.state) { [weak self] slot, value in
                if slot.state == .validCard {
                    self?.beginSession(withSlot: slot)
                }
                print("🪪 TKSmartCardSlot.state changed to: \(slot.state)")
            }
        }
    }
    
    private func beginSession(withSlot slot: TKSmartCardSlot) {
        self.currrentSlot = slot
        if let smartCard = slot.makeSmartCard() {
            smartCard.beginSession { [weak self] success, error in
                if success {
                    self?.currentSmartCard = smartCard
                    self?.connectingCallback?(.success(smartCard))
                    self?.connectingCallback = nil
                    self?.observeManagerChanges()
                } else {
                    self?.connectingCallback?(.failure(error ?? "🪪 Failed but got no error!"))
                    self?.connectingCallback = nil
                }
            }
        }
    }
    
    internal func endSession() {
        print("🪪 End SmartCard session")
        connectingCallback = nil
        closingCallback = nil
        slotObservation = nil
        managerObservation = nil
        currentSmartCard?.endSession()
        currentSmartCard = nil
        currrentSlot = nil
    }
}
