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
    private var connectingContinuation: CheckedContinuation<TKSmartCard, Error>?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var managerObservation: NSKeyValueObservation?
    private var slotObservation: NSKeyValueObservation?

    public func connectionDidClose() async -> Error? {
        return await withCheckedContinuation { continuation in
            closingContinuations.append(continuation)
        }
    }
    
    // 1. waiting for initial connection OR 2. already connected and waiting for disconnect
    private func observeManagerChanges(continuation: CheckedContinuation<TKSmartCard, Error>? = nil) {
        self.connectingContinuation = continuation
        self.managerObservation = self.manager?.observe(\TKSmartCardSlotManager.slotNames) { [weak self] manager, value in
            print("Got changes in slotNames: \(value)")
            
            if manager.slotNames.isEmpty {
                print("TKSmartCardSlot removed")
                self?.closingContinuations.forEach { continuation in
                    continuation.resume(returning: nil)
                }
                self?.currrentSlot = nil
                self?.closingContinuations.removeAll()
                return
            }
            
            if continuation != nil, let slotName = manager.slotNames.first {
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
                    smartCard.beginSession { result, error in
                        if result {
                            self?.connectingContinuation?.resume(returning: smartCard)
                            // Observe disconnect only
                            self?.observeManagerChanges()
                        } else {
                            self?.connectingContinuation?.resume(throwing: error ?? "Failed but got no error!")
                        }
                        return
                        
                    }
                }
            }
            print("TKSmartCardSlot.state changed to: \(slot.state)")
        }
    }
    
    func connect() async throws -> TKSmartCard {
        // Only allow one call to connect() for each instance of SmartCardManager
        guard connectingContinuation == nil else {
            throw "connect() can only be called once for each instance of SmartCardManager"
        }
        
        return try await withCheckedThrowingContinuation { [weak self] continuation in
            guard let manager = self?.manager else {
                continuation.resume(throwing: "No default TKSmartCardSlotManager, check entitlemenst for com.apple.smartcard.")
                return
            }
            
            if let slotName = manager.slotNames.first,
               let slot = manager.slotNamed(slotName),
               let smartCard = slot.makeSmartCard() {
                smartCard.beginSession { result, error in
                    if result {
                        continuation.resume(returning: smartCard)
                        // Observe disconnect only
                        self?.observeManagerChanges()
                    } else {
                        continuation.resume(throwing: error ?? "Failed but got no error!")
                    }
                }
            } else {
                // Observe new connection and its subsequent disconnect
                self?.observeManagerChanges(continuation: continuation)
            }
        }
    }
}

public final class SmartCardConnection: Connection, InternalConnection {
    
    private static var connection: SmartCardConnection?
    private static var manager: SmartCardManager?
    @MainActor private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()

    internal var session: Session?
    private var smartCard: TKSmartCard
    
    // A Connection is not a true singleton as it will be dealloced once the connection has been closed.
    @MainActor public static func connection() async throws -> Connection {
        print("SmartCardConnection connection() called")
        if let connection = self.connection {
            print("reuse SmartCardConnection")
            return connection
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            if connectionContinuations.isEmpty {
                print("No current connection in progress, let start a new one.")
                connectionContinuations.append(continuation)
                Task {
                    do {
                        let connection = try await SmartCardConnection()
                        connectionContinuations.forEach { continuation in
                            print("Return Connection to listeners.")
                            continuation.resume(returning: connection)
                        }
                    } catch {
                        connectionContinuations.forEach { continuation in
                            print("Throw Error to listeners.")
                            continuation.resume(throwing: error)
                        }
                    }
                    print(connectionContinuations)
                    print("Got connection, clear continuations.")
                    connectionContinuations.removeAll()
                }
            } else {
                print("Waiting for connection, let's NOT start another connection.")
                connectionContinuations.append(continuation)
            }
        }
    }
    
    private init() async throws {
        if Self.manager == nil {
            Self.manager = SmartCardManager()
        }
        smartCard = try await Self.manager!.connect()
        Self.connection = self
    }

    public func close(result: Result<String, Error>?) async {
        smartCard.endSession()
    }
    
    public func connectionDidClose() async -> Error? {
        let error = await Self.manager?.connectionDidClose()
        Self.connection = nil
        Self.manager = nil
        return error
    }
    
    public func send(apdu: APDU) async throws -> Data {
        return try await smartCard.transmit(apdu.apduData)
    }
}
