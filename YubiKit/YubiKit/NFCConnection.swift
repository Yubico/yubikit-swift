//
//  NFCConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

#if os(iOS)
import Foundation
import CoreNFC

public final actor NFCConnection: Connection, InternalConnection {
    
    private static let manager = NFCConnectionManager()
    
    public static func connection() async throws -> Connection {
        print("🛜 NFCConnection, connection() on \(Thread.current)")
        return try await manager.connection()
    }
    
    var _session: Session?
    func session() async -> Session? {
        return _session
    }
    func setSession(_ session: Session?) async {
        _session =  session
    }
    private var tag: NFCISO7816Tag?
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: ((Result<String, Error>?) -> Void)?
    
    private init() { }
    
    fileprivate init(tag: NFCISO7816Tag, closingHandler handler: @escaping (Result<String, Error>?) -> Void) {
        self.tag = tag
        self.closingHandler = handler
    }
    
    private func close(result: Result<String, Error>?) async {
        print("🛜 NFCConnection, close in thread \(Thread.current)")
        closingHandler?(result)
        tag = nil
        closingContinuations.forEach { continuation in
            continuation.resume(returning: result?.error)
        }
        print("🛜 NFCConnection, messaged all continuations, let remove them in thread \(Thread.current)")
        closingContinuations.removeAll()
    }
    
    // NFCConnection can be closed with an optional message in addition to the close method defined in the Connection protocol.
    // The message will be displayed on the NFC modal when it dismisses.
    public func close(message: String?) async {
        if let message {
            await close(result: .success(message))
        } else {
            await close(result: nil)
        }
    }
    
    public func close(error: Error?) async {
        if let error {
            await close(result: .failure(error))
        } else {
            await close(result: nil)
        }
    }
    
    // Wait for the connection to close
    public func connectionDidClose() async -> Error? {
        print("🛜 NFCConnection, await connectionDidClose() called in thread \(Thread.current)")
        if tag == nil {
            print("🛜 NFCConnection, await connectionDidClose() baling out since connection is already closed")
            return nil
        }
        return await withCheckedContinuation { continuation in
            print("🛜 NFCConnection, append closingContinuation in thread \(Thread.current)")
            closingContinuations.append(continuation)
        }
    }
    
    // Send apdu over connection
    public func send(apdu: APDU) async throws -> Response {
        print("🛜 NFCConnection, send(apdu: \(apdu))")
        guard let tag else { throw "No NFC tag" }
        guard let apdu = apdu.nfcIso7816Apdu else { throw "Malformed APDU data" }
        let result: (Data, UInt8, UInt8) = try await tag.sendCommand(apdu: apdu)
        return Response(data: result.0, sw1: result.1, sw2: result.2)
    }
    
    deinit {
        print("🛜 deinit NFCConnection")
    }
}


fileprivate actor NFCConnectionManager {
    
    let nfcWrapper = NFCTagWrapper()
    var currentConnection: NFCConnection?
    
    var connectionTask: Task<NFCConnection, Error>?
    func connection() async throws -> NFCConnection {
        let task = Task { [connectionTask] in
            if let connectionTask {
                print("🛜 NFCManager, cancel previous task.")
            }
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
    
    // Only allow one connect() at a time
    private func _connection() async throws -> NFCConnection {
        print("🛜 NFCManager, _connection()")
        
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
                print("🛜 NFCManager, will call nfcWrapper.connection(), Task.isCancelled = \(Task.isCancelled)")
                nfcWrapper.connection { result in
                    print("🛜 NFCManager, _connection() got result \(result) pass it to \(String(describing: continuation))")
                    switch result {
                    case .success(let tag):
                        let connection = NFCConnection(tag: tag, closingHandler: { [weak self] result in
                            self?.nfcWrapper.endSession(result: result)
                        })
                        self.currentConnection = connection
                        continuation.resume(returning: connection)
                    case .failure(let error):
                        continuation.resume(throwing: error)
                        print("🛜 NFCManager, remove \(String(describing: continuation)) after failure")
                    }
                }
            }
        } onCancel: {
            print("🛜 NFCManager onCancel: called on \(Thread.current)")
            nfcWrapper.endSession(result: nil)
        }
    }
    
    func didDisconnect() async -> Error? {
        return await withTaskCancellationHandler {
            return await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in // try to remove variable definition in the future
                nfcWrapper.connectionDidClose { error in
                    continuation.resume(returning: error)
                }
            }
        } onCancel: {
            print("NFCManagerActor didDisconnect(), onCancel: called on \(Thread.current)")
        }
    }
}

fileprivate class NFCTagWrapper: NSObject, NFCTagReaderSessionDelegate {
     
    private var tagSession: NFCTagReaderSession?
    private let queue = DispatchQueue(label: "com.yubico.nfc-connection", qos: .background)
    
    enum State {
        case ready, scanning, connected(NFCISO7816Tag)
    }
    private var state = State.ready
    
    private var connectingHandler: ((Result<NFCISO7816Tag, Error>) -> Void)?
    private var closingHandler: ((Error?) -> Void)?
    
    internal func connection(completion handler: @escaping (Result<NFCISO7816Tag, Error>) -> Void) {
        queue.async {
            print("🛜 NFCWrapper, connection()")
            self.closingHandler?("Closed by new call to connection()")
            self.closingHandler = nil
            self.connectingHandler?(.failure("Cancelled by new call to connection()"))
            self.connectingHandler = handler
            
            switch self.state {
            case .ready:
                self.tagSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
                self.tagSession?.begin()
                self.state = .scanning
            case .scanning:
                return
            case .connected(let tag):
                self.connectingHandler?(.success(tag))
                self.connectingHandler = nil
            }
        }
    }
    
    internal func connectionDidClose(completion handler: @escaping (Error?) -> Void) {
        queue.async {
            print("🪪 NFCWrapper, connectionDidClose()")
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    func endSession(result: Result<String, Error>?) {
        queue.async {
            if let result {
                switch result {
                case .success(let message):
                    self.tagSession?.alertMessage = message
                    self.tagSession?.invalidate()
                case .failure(let error):
                    self.tagSession?.invalidate(errorMessage: error.localizedDescription)
                }
            } else {
                self.tagSession?.invalidate()
            }
            self.tagSession = nil
            self.state = .ready
        }
    }
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        queue.async {
            self.state = .scanning
            self.tagSession = session
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        queue.async {
            self.connectingHandler?(.failure(error))
            self.connectingHandler = nil
            self.closingHandler?(error)
            self.closingHandler = nil
            self.state = .ready
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        queue.async {
            guard let tag = tags.first else { return }
            self.tagSession?.connect(to: tag) { error in
                if let error {
                    self.connectingHandler?(.failure(error))
                    self.connectingHandler = nil
                    return
                }
                if case let NFCTag.iso7816(tag) = tag {
                    self.state = .connected(tag)
                    self.connectingHandler?(.success(tag))
                } else {
                    self.connectingHandler?(.failure("Not an iso7816 tag!"))
                }
                self.connectingHandler = nil
            }
        }
    }
}

extension Connection {
    public var nfcConnection: NFCConnection? {
        self as? NFCConnection
    }
}

extension NFCTagWrapper.State: Equatable {
    fileprivate static func == (lhs: NFCTagWrapper.State, rhs: NFCTagWrapper.State) -> Bool {
        switch (lhs, rhs) {
        case (.ready, .ready), (.scanning, .scanning):
            return true
        case (.connected(let rhsTag), .connected(let lhsTag)):
            return rhsTag.identifier == lhsTag.identifier
        default:
            return false
        }
    }
}

extension APDU {
    var nfcIso7816Apdu: NFCISO7816APDU? {
        return NFCISO7816APDU(data: self.data)
    }
}

extension Result {
    var error: Error? {
        switch self {
        case .failure(let error):
            return error
        default:
            return nil
        }
    }
}

#endif
