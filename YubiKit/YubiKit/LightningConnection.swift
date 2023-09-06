//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-23.
//

#if os(iOS)

import Foundation
import ExternalAccessory


public final class LightningConnection: Connection, InternalConnection {
    
    private let commandProcessingTime = 0.002;

    private static var connection: LightningConnection?
    private static var manager = LightningManager()
    private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()
    private static var connectingLock = NSLock()
    private static var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private static var closingLock = NSLock()

    internal var session: Session?
    private var lightningSession: EASession?

    private init(session: EASession) {
        print("⚡️ init LightningSession")
        session.inputStream?.schedule(in: .current, forMode: .common)
        session.outputStream?.schedule(in: .current, forMode: .common)
        session.inputStream?.open()
        session.outputStream?.open()
        self.lightningSession = session
    }

    public func send(apdu: APDU) async throws -> Response {
        guard let lightningSession, let outputStream = lightningSession.outputStream, let inputStream = lightningSession.inputStream else { throw "No current session" }
        var data = Data([0x00]) // YLP iAP2 Signal
        data.append(apdu.data)
        try outputStream.writeToYubiKey(data: data)
        while true {
            try await Task.sleep(for: .seconds(commandProcessingTime))
            let result = try inputStream.readFromYubiKey()
            if result.isEmpty { throw "Empty result" }
//            let response = Response(rawData: result)
            let status = Response.StatusCode(data: result.subdata(in: result.count-2..<result.count))
            print("⚡️ result (\(status)): \(result.hexEncodedString)")

            // BUG #62 - Workaround for WTX == 0x01 while status is 0x9000 (success).
            if (status == .ok) || result.bytes[0] != 0x01 {
                if result.bytes[0] == 0x00 { // Remove the YLP key protocol header
                    return Response(rawData: result.subdata(in: 1..<result.count))
                } else if result.bytes[0] == 0x01 { // Remove the YLP key protocol header and the WTX
                    return Response(rawData: result.subdata(in: 4..<result.count))
                }
                throw "Wrong respnse"
            }
        }
    }
    
    // Starts lightning and wait for a connection
    @MainActor public static func connection() async throws -> Connection {
        print("⚡️ LightningConnection connection() called")

        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                connectingLock.with {
                    if let connection = self.connection {
                        print("⚡️ reuse LightningConnection")
                        continuation.resume(returning: connection)
                        return
                    }
                    
                    if Self.connectionContinuations.isEmpty {
                        print("⚡️ No current connection in progress, let start a new one.")
                        connectionContinuations.append(continuation)
                        manager.connect { result in
                            print("⚡️ Got result, now wait for lock")
                            switch result {
                            case .success(let session):
                                let connection = LightningConnection(session: session)
                                Self.connection = connection
                                connectionContinuations.forEach { continuation in
                                    print("⚡️ Send connection \(connection) to continuation \(continuation)")
                                    continuation.resume(returning: connection)
                                }
                                print("⚡️ Got connection \(connection), clear continuations \(connectionContinuations.count).")
                                connectionContinuations.removeAll()
                            case .failure(let error):
                                connectionContinuations.forEach { continuation in
                                    continuation.resume(throwing: error)
                                }
                                print("⚡️ Got error, clear continuations.")
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
                print("⚡️ Cancel all continuations!")
                connectionContinuations.forEach { continuation in
                    continuation.resume(throwing: CancellationError())
                }
                manager.endSession()
                connectionContinuations.removeAll()
            }
        }
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
                print("⚡️ Cancel connectionDidClose()")
                Self.closingContinuations.forEach { continuation in
                    continuation.resume(returning: CancellationError())
                }
                Self.closingContinuations.removeAll()
                // should we end the session when the close task is cancelled?
                Self.manager.endSession()
            }
        }
    }
    
    public func close() {
        Self.manager.endSession()
        self.session = nil
    }
    
    deinit {
        print("⚡️ deinit LightningConnection")
    }
}


extension EAAccessory {
    var isYubiKey: Bool {
        return self.protocolStrings.contains("com.yubico.ylp") && self.manufacturer == "Yubico"
    }
}

fileprivate class LightningManager {
    private let manager = EAAccessoryManager.shared()
    private var currentAccessory: EAAccessory?
    private var currentSession: EASession?
    private var connectingCallback: ((Result<EASession, Error>) -> Void)? = nil
    private var closingCallback: ((Error?) -> Void)? = nil
    
    init() {
        NotificationCenter.default.addObserver(forName: .EAAccessoryDidConnect, object: self.manager, queue: nil) { [weak self] notification in
            guard self?.connectingCallback != nil, let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory else { return }
            self?.connectAccessory(accessory)
        }
        NotificationCenter.default.addObserver(forName: .EAAccessoryDidDisconnect, object: self.manager, queue: nil) { [weak self] notification in
            guard self?.closingCallback != nil, let accessory = notification.userInfo?[EAAccessoryKey] as? EAAccessory else { return }
            self?.disconnectAccessory(accessory)
        }
        EAAccessoryManager.shared().registerForLocalNotifications()
    }
    
    internal func connect(_ callback: @escaping (Result<EASession, Error>) -> Void) {
        guard connectingCallback == nil else {
            fatalError("Lightning connecting callback already registered!")
        }
        self.connectingCallback = callback
        if let connectedKey = manager.connectedAccessories.filter({ accessory in
            accessory.isYubiKey
        }).first {
            connectAccessory(connectedKey)
        }
    }
    
    private func connectAccessory(_ accessory: EAAccessory) {
        guard accessory.isYubiKey else { return }
        guard let session = EASession(accessory: accessory, forProtocol: "com.yubico.ylp") else { return }
        self.currentAccessory = accessory
        self.currentSession = session
        self.connectingCallback?(.success(session))
        self.connectingCallback = nil
    }
    
    private func disconnectAccessory(_ accessory: EAAccessory) {
        guard accessory.isYubiKey else { return }
        if self.currentSession?.accessory == accessory {
            self.closingCallback?(nil)
            self.closingCallback = nil
            self.currentAccessory = nil
            self.currentSession = nil
        }
    }
    
    internal func connectionDidClose(_ callback: @escaping (Error?) -> Void) {
        guard closingCallback == nil else {
            fatalError("⚡️ Closing callback already registered!")
        }
        closingCallback = callback
    }
    
    internal func endSession() {
        print("⚡️ End Lightning session")
        connectingCallback = nil
        closingCallback = nil
        currentSession?.inputStream?.close()
        currentSession?.outputStream?.close()
        currentAccessory = nil
        currentSession = nil
    }
}

#endif
