//
//  SmartCardConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-06-21.
//

import Foundation
import CryptoTokenKit


fileprivate class SmartCardManager {
    
    private let manager = TKSmartCardSlotManager.default
    private var currrentSlot: TKSmartCardSlot?
    private var connectingCallback: ((Result<TKSmartCard, Error>) -> Void)? = nil
    private var closingCallback: ((Error?) -> Void)? = nil
    private var managerObservation: NSKeyValueObservation?
    private var slotObservation: NSKeyValueObservation?

    public func connect(_ callback: @escaping (Result<TKSmartCard, Error>) -> Void) {
        guard connectingCallback == nil else {
            fatalError("Connecting callback already registered!")
        }

        guard let manager else {
            callback(.failure("No default TKSmartCardSlotManager, check entitlemenst for com.apple.smartcard."))
            return
        }
        
        self.connectingCallback = callback
        
        if let slotName = manager.slotNames.first, let slot = manager.slotNamed(slotName), let smartCard = slot.makeSmartCard() {
            smartCard.beginSession { [weak self] success, error in
                self?.handleSession(smartCard: smartCard, success: success, error: error)
            }
        } else {
            // Observe new connection and its subsequent disconnect
            self.observeManagerChanges()
        }
        
    }
    
    public func connectionDidClose(_ callback: @escaping (Error?) -> Void) {
        guard closingCallback == nil else {
            fatalError("Closing callback already registered!")
        }
        closingCallback = callback
    }
    
    // 1. waiting for initial connection OR 2. already connected and waiting for disconnect
    private func observeManagerChanges() {
        slotObservation = manager?.observe(\TKSmartCardSlotManager.slotNames) { [weak self] manager, value in
            print("Got changes in slotNames: \(value)")
            if manager.slotNames.isEmpty {
                print("TKSmartCardSlot removed")
                self?.closingCallback?(nil)
                self?.currrentSlot = nil
                self?.closingCallback = nil
                return
            }
            if self?.connectingCallback != nil, let slotName = manager.slotNames.first {
                manager.getSlot(withName: slotName) { slot in
                    self?.observeSlotChanges(slot: slot!)
                }
            }
        }
    }

    private func observeSlotChanges(slot: TKSmartCardSlot) {
        print("Start observing changes to the current TKSmartCardSlot")
        currrentSlot = slot
        slotObservation = currrentSlot?.observe(\TKSmartCardSlot.state) { [weak self] slot, value in
            if slot.state == .validCard {
                if let smartCard = self?.currrentSlot?.makeSmartCard() {
                    smartCard.beginSession { [weak self] success, error in
                        self?.handleSession(smartCard: smartCard, success: success, error: error)
                    }
                }
            }
            print("TKSmartCardSlot.state changed to: \(slot.state)")
        }
    }
    
    private func handleSession(smartCard: TKSmartCard, success: Bool, error: Error?) {
        if success {
            connectingCallback?(.success(smartCard))
            connectingCallback = nil
            observeManagerChanges()
        } else {
            connectingCallback?(.failure(error ?? "Failed but got no error!"))
            connectingCallback = nil
        }
    }
}

public final class SmartCardConnection: Connection, InternalConnection {
    
    private static var connection: SmartCardConnection?
    private static var manager = SmartCardManager()
    private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()
    private static var connectingLock = NSLock()
    private static var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private static var closingLock = NSLock()

    internal var session: Session?
    private var smartCard: TKSmartCard
    
    // A Connection is not a true singleton as it will be dealloced once the connection has been closed.
    @MainActor public static func connection() async throws -> Connection {
        print("SmartCardConnection connection() called")
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                connectingLock.with {
                    if let connection = self.connection {
                        print("reuse SmartCardConnection")
                        continuation.resume(returning: connection)
                        return
                    }
                    
                    if Self.connectionContinuations.isEmpty {
                        print("No current connection in progress, let start a new one.")
                        connectionContinuations.append(continuation)
                        manager.connect { result in
                            connectingLock.with {
                                switch result {
                                case .success(let smartCard):
                                    let connection = SmartCardConnection(smartCard: smartCard)
                                    Self.connection = connection
                                    connectionContinuations.forEach { continuation in
                                        continuation.resume(returning: connection)
                                    }
                                case .failure(let error):
                                    connectionContinuations.forEach { continuation in
                                        continuation.resume(throwing: error)
                                    }
                                    print("Got connection, clear continuations.")
                                    connectionContinuations.removeAll()
                                }
                            }
                            
                        }
                    } else {
                        connectionContinuations.append(continuation)
                    }
                }
            }
        } onCancel: {
            connectingLock.with {
                print("Cancel all continuations!")
                connectionContinuations.forEach { continuation in
                    continuation.resume(throwing: CancellationError())
                }
                connectionContinuations.removeAll()
            }
        }
    }
    
    private init(smartCard: TKSmartCard) {
        self.smartCard = smartCard
    }

    public func close(result: Result<String, Error>?) async {
        smartCard.endSession()
    }
    
    public func connectionDidClose() async -> Error? {
        return await withTaskCancellationHandler {
            return await withCheckedContinuation { continuation in
                Self.closingLock.with {
                    if Self.closingContinuations.isEmpty {
                        Self.closingContinuations.append(continuation)
                        Self.manager.connectionDidClose { error in
                            Self.closingContinuations.forEach { $0.resume(returning: error) }
                        }
                    } else {
                        Self.closingContinuations.append(continuation)
                    }
                }
            }
        } onCancel: {
            Self.closingLock.with {
                print("Cancel connectionDidClose()")
                Self.closingContinuations.forEach { continuation in
                    continuation.resume(returning: CancellationError())
                }
                Self.closingContinuations.removeAll()
            }
        }
    }
    
    public func send(apdu: APDU) async throws -> Data {
        let result = try await smartCard.transmit(apdu.apduData)
        print("SmarCard result: \(result.hexEncodedString)")
        return result
    }
}
