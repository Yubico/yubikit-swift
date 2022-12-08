//
//  NFCConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

#if os(iOS)
import Foundation
import CoreNFC

fileprivate final class TagReaderSession: NSObject, NFCTagReaderSessionDelegate {
    
    private typealias NFCTagContinuation = CheckedContinuation<NFCTag, Error>
    private var nfcTagContinuation: NFCTagContinuation?
    private var tagSession: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    
    func connect() async throws -> NFCISO7816Tag {
        let tag = try await self.getTag()
        
        guard NFCTagReaderSession.readingAvailable else { throw "No NFC for you"}
        try await self.tagSession?.connect(to: tag)
        
        if case let NFCTag.iso7816(tag) = tag {
            return tag
        } else {
            throw "Not a NFCISO7816Tag"
        }
    }
    
    private func getTag() async throws -> NFCTag {
        self.tagSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        tagSession?.begin()
        return try await withCheckedThrowingContinuation { connectingContinuation in
            self.nfcTagContinuation = connectingContinuation
        }
    }
    
    func close() {
        tagSession?.invalidate()
    }
    
    func tagReaderSessionDidBecomeActive(_ tagSession: NFCTagReaderSession) {
        self.tagSession = tagSession
        print("Got session: \(tagSession)")
    }
    
    func tagReaderSession(_ tagSession: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // we need to handle both failing initial connection and later disconnect
        print("NFC session invalidated with error: \(error)")
        self.tagSession = nil
        nfcTagContinuation?.resume(throwing: error)
        nfcTagContinuation = nil
    }
    
    func tagReaderSession(_ tagSession: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        print("Got tags: \(tags)")
        nfcTagContinuation?.resume(returning: tags.first!)
        nfcTagContinuation = nil
    }
}

public final class NFCConnection: Connection, InternalConnection {

    static var connection: NFCConnection?
    
    var session: Session?
//    var closingError: Error?
    
    static private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    static private var connectionContinuations = [CheckedContinuation<Connection, Error>]()

//    let closingSemaphore = DispatchSemaphore(value: 0)
    private let tagReaderSession = TagReaderSession()
    private let tag: NFCISO7816Tag

    private init() async throws {
        tag = try await tagReaderSession.connect()
        Self.connection = self
    }
    
    public func send(apdu: APDU) async throws -> Response {
        guard tag.isAvailable else { throw "Tag not available" }
        guard let apdu = apdu.nfcIso7816Apdu else { throw "Malformed APDU data" }
        let result: (Data, UInt8, UInt8) = try await tag.sendCommand(apdu: apdu)
        return Response(data: result.0, sw1: result.1, sw2: result.2)
    }
    
    public func connectionDidClose() async-> Error? {
        return await withCheckedContinuation { continuation in
            Self.closingContinuations.append(continuation)
        }
    }
    
    // Starts NFC and wait for a connection
    public static func connection() async throws -> Connection {
        print("NFCConnection connection() called")
        if let connection {
            print("reuse NFC connection")
            return connection
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            if connectionContinuations.isEmpty {
                print("No current connection in progress, let start a new one.")
                connectionContinuations.append(continuation)
                Task {
                    do {
                        let connection = try await NFCConnection()
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
    
    public func close(result: Result<String, Error>? = nil) {
        print("Closing NFC Connection")
        self.tagReaderSession.close()
        Self.closingContinuations.forEach { continuation in
            continuation.resume(returning: nil)
        }
        Self.closingContinuations.removeAll()
        Self.connection = nil
    }
}

extension APDU {
    var nfcIso7816Apdu: NFCISO7816APDU? {
        return NFCISO7816APDU(data: self.apduData)
    }

}
#endif
