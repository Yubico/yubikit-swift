//
//  NFCConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

#if os(iOS)
import Foundation
import CoreNFC

fileprivate final class TagManager: NSObject, NFCTagReaderSessionDelegate {
    
    private var tagSession: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var connectingCallback: ((Result<NFCISO7816Tag, Error>) -> Void)? = nil
    private var closingCallback: ((Error?) -> Void)? = nil
    
    internal func connect(_ callback: @escaping (Result<NFCISO7816Tag, Error>) -> Void) {
        self.connectingCallback = callback
        self.tagSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        self.tagSession?.begin()
    }
    
    internal func connectionDidClose(_ callback: @escaping (Error?) -> Void) {
        guard closingCallback == nil else {
            fatalError("Closing callback already registered!")
        }
        closingCallback = callback
    }
    
    func endSession(result: Result<String, Error>?) {
        if let result {
            switch result {
            case .success(let message):
                tagSession?.alertMessage = message
                tagSession?.invalidate()
            case .failure(let error):
                tagSession?.invalidate(errorMessage: error.localizedDescription)
            }
        } else {
            tagSession?.invalidate()
        }
    }
    
    func tagReaderSessionDidBecomeActive(_ tagSession: NFCTagReaderSession) {
        self.tagSession = tagSession
        print("Got session: \(tagSession)")
    }
    
    func tagReaderSession(_ tagSession: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // we need to handle both failing initial connection and later disconnect
        print("NFC session invalidated with error: \(error)")
        self.tagSession = nil
        self.connectingCallback?(.failure(error))
        self.connectingCallback = nil
        self.closingCallback?(error)
        self.closingCallback = nil
    }
    
    func tagReaderSession(_ tagSession: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        print("Got tags: \(tags)")
        let tag = tags.first!
        
        self.tagSession?.connect(to: tag) { error in
            if let error { self.connectingCallback?(.failure(error)); self.connectingCallback = nil; return }
            if case let NFCTag.iso7816(tag) = tag {
                self.connectingCallback?(.success(tag))
            } else {
                self.connectingCallback?(.failure("Not an iso7816 tag!"))
            }
            self.connectingCallback = nil
        }
    }
}

public final class NFCConnection: Connection, InternalConnection {

    private static var connection: NFCConnection?
    private static let manager = TagManager()
    private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()
    private static var connectingLock = NSLock()
    private static var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private static var closingLock = NSLock()

    internal var session: Session?
    private var tag: NFCISO7816Tag

    private init(tag: NFCISO7816Tag) {
        self.tag = tag
    }
    
    public func send(apdu: APDU) async throws -> Response {
        guard tag.isAvailable else { throw "Tag not available" }
        guard let apdu = apdu.nfcIso7816Apdu else { throw "Malformed APDU data" }
        let result: (Data, UInt8, UInt8) = try await tag.sendCommand(apdu: apdu)
        return Response(data: result.0, sw1: result.1, sw2: result.2)
    }
    
    // Starts NFC and wait for a connection
    @MainActor public static func connection() async throws -> Connection {
        print("NFCConnection connection() called")
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                connectingLock.with {
                    if let connection = self.connection {
                        print("Reuse NFCConnection")
                        continuation.resume(returning: connection)
                        return
                    }
                    
                    if Self.connectionContinuations.isEmpty {
                        print("No current connection in progress, let start a new one.")
                        connectionContinuations.append(continuation)
                        manager.connect { result in
                            switch result {
                            case .success(let tag):
                                let connection = NFCConnection(tag: tag)
                                Self.connection = connection
                                connectionContinuations.forEach { continuation in
                                    continuation.resume(returning: connection)
                                }
                                connectionContinuations.removeAll()
                            case .failure(let error):
                                connectionContinuations.forEach { continuation in
                                    continuation.resume(throwing: error)
                                }
                                print("Got connection, clear continuations.")
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
                print("Cancel all continuations!")
                connectionContinuations.forEach { continuation in
                    continuation.resume(throwing: CancellationError())
                }
                manager.endSession(result: nil)
                connectionContinuations.removeAll()
            }
        }
    }
    
    public func close() {
        close(result: nil)
    }
    
    public func close(result: Result<String, Error>? = nil) {
        print("Closing NFC Connection")
        Self.manager.endSession(result: result)
        Self.connection = nil
        self.session = nil
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
                print("Cancel connectionDidClose()")
                Self.closingContinuations.forEach { continuation in
                    continuation.resume(returning: CancellationError())
                }
                Self.closingContinuations.removeAll()
                // should we end the session when the close task is cancelled?
                Self.manager.endSession(result: nil)
            }
        }
    }
}

extension APDU {
    var nfcIso7816Apdu: NFCISO7816APDU? {
        return NFCISO7816APDU(data: self.data)
    }

}
#endif
